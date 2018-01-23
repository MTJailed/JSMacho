/*
	A MACH-O Parser written in Vanilla Javascript
	Created by Sem Voigtländer

	The code is licensed under MIT-License.
	With the addition that the license can be changed at any time without consent.
	
	The MACH-O File Format is a format commonly used by Apple in their Operating Systems.
	This script was written to parse a MACH-O binary to get information about it.

*/

/*
	The MACH header appears at the beginning of the file.
	It is the same for both 32 and 64 bit.
	
	In C the MACH header looks like this:
	
		struct mach_header {
			uint32_t	magic;				// mach magic number identifier
			cpu_type_t	cputype;			// cpu specifier
			cpu_subtype_t	cpusubtype;		// machine specifier
			uint32_t	filetype;			// type of file
			uint32_t	ncmds;				// number of load commands
			uint32_t	sizeofcmds;			// the size of all the load commands
			uint32_t	flags;				// flags
		};
	
	The 64-bit MACH header appears only at the beginning of files for 64-bit architecture.
	In C it looks like this:

		struct mach_header {
			uint32_t	magic;				// mach magic number identifier
			cpu_type_t	cputype;			// cpu specifier
			cpu_subtype_t	cpusubtype;		// machine specifier
			uint32_t	filetype;			// type of file
			uint32_t	ncmds;				// number of load commands
			uint32_t	sizeofcmds;			// the size of all the load commands
			uint32_t	flags;				// flags
			uint32_t reserved;				// reserved
		};
*/


//Check for dependencies
if(!endianReader) {
	throw new Error('This script depends on endian-reader.js');
}
if(!buffer.Buffer) {
	throw new Error('This script depends on buffer.min.js');
}


//Macho Object, used to compare with in the parser
var Macho = [ Object ];

Macho.MH_MAGIC = 0xfeedface; //32 and 64-bit mach header
Macho.MH_MAGIC64 = 0xfeedfacf; //64-bit mach header

//Processor architecture
Macho.cpuArch = {
	mask: 0xff000000,
  	abi64: 0x01000000
};

//Processor Type
Macho.cpuType = {
  0x01: 'vax',
  0x06: 'mc680x0',
  0x07: 'i386',
  0x01000007: 'x86_64',
  0x0a: 'mc98000',
  0x0b: 'hppa',
  0x0c: 'arm',
  0x0100000c: 'arm64',
  0x0d: 'mc88000',
  0x0e: 'sparc',
  0x0f: 'i860',
  0x10: 'alpha',
  0x12: 'powerpc',
  0x01000012: 'powerpc64'
};

//Endianness of the Mach-o File
Macho.endianness = {
	0xffffffff: 'multiple',
	0: 'little_endian',
	1: 'big_endian'
};

//Processor subtype
Macho.cpuSubType = {
	mask: 0x00ffffff,
	vax: {
		0: 'all',
	    1: '780',
	    2: '785',
	    3: '750',
	    4: '730',
	    5: 'I',
	    6: 'II',
	    7: '8200',
	    8: '8500',
	    9: '8600',
	    10: '8650',
	    11: '8800',
	    12: 'III'
	},
	mc680x0: {
	    1: 'all',
	    2: '40',
	    3: '30_only'
	  },
	  i386: {}, //32-bit Intel processors
	  x86_64: {
	    3: 'all', //64/32-bit desktop AMD and Intel processors
	    4: 'arch1'
	  },
	  mips: {
	    0: 'all',
	    1: 'r2300',
	    2: 'r2600',
	    3: 'r2800',
	    4: 'r2000a',
	    5: 'r2000',
	    6: 'r3000a',
	    7: 'r3000'
	  },
	  mc98000: {
	    0: 'all',
	    1: 'mc98601'
	  },
	  hppa: {
	    0: 'all',
	    1: '7100lc'
	  },
	  mc88000: {
	    0: 'all',
	    1: 'mc88100',
	    2: 'mc88110'
	  },
	  sparc: {
	    0: 'all'
	  },
	  i860: {
	    0: 'all',
	    1: '860'
	  },
	  powerpc: {
	    0: 'all',
	    1: '601',
	    2: '602',
	    3: '603',
	    4: '603e',
	    5: '603ev',
	    6: '604',
	    7: '604e',
	    8: '620',
	    9: '750',
	    10: '7400',
	    11: '7450',
	    100: '970'
	  },
	  arm: {
	    0: 'all',
	    5: 'v4t',
	    6: 'v6',
	    7: 'v5tej',
	    8: 'xscale',
	    9: 'v7', //32-bit iPhones
	    10: 'v7f',
	    11: 'v7s',
	    12: 'v7k',
	    14: 'v6m',
	    15: 'v7m',
	    16: 'v7em'
	  }
};

function cpuSubTypeIntel(a, b, name)
{
	Macho.cpuSubType.i386[a + (b << 4)] = name;
}
//Intel's 32-bit processor subtypes, might need to be extended though.
[
  [3, 0, 'all'],
  [4, 0, '486'],
  [4, 8, '486sx'],
  [5, 0, '586'],
  [6, 1, 'pentpro'],
  [6, 3, 'pentII_m3'],
  [6, 5, 'pentII_m5'],
  [7, 6, 'celeron'],
  [7, 7, 'celeron_mobile'],
  [8, 0, 'pentium_3'],
  [8, 1, 'pentium_3_m'],
  [8, 2, 'pentium_3_xeon'],
  [9, 0, 'pentium_m'],
  [10, 0, 'pentium_4'],
  [10, 1, 'pentium_4_m'],
  [11, 0, 'itanium'],
  [11, 1, 'itanium_2'],
  [12, 0, 'xeon'],
  [12, 1, 'xeon_mp']
].forEach(function(item) {
  cpuSubTypeIntel(item[0], item[1], item[2]);
});

//What sort of file file are we looking at
Macho.fileType = {
	1: 'object',
	2: 'execute', //normal executable
	3: 'fvmlib',
	4: 'core', //core dump, mostly generated after a crash
	5: 'preload',
	6: 'dylib', //dynamic library
	7: 'dylinker', //dynamic linker (e.g. dyld) not commonly used
	8: ' bundle', //bundle file, loaded into process at runtime
	9: 'dylib_stub',
	10: 'dsym',
	11: 'kext' //kernel extension
};

Macho.flags = {
  0x1: 'noundefs',
  0x2: 'incrlink',
  0x4: 'dyldlink',
  0x8: 'bindatload',
  0x10: 'prebound',
  0x20: 'split_segs',
  0x40: 'lazy_init',
  0x80: 'twolevel',
  0x100: 'force_flat',
  0x200: 'nomultidefs',
  0x400: 'nofixprebinding',
  0x800: 'prebindable',
  0x1000: 'allmodsbound',
  0x2000: 'subsections_via_symbols',
  0x4000: 'canonical',
  0x8000: 'weak_defines',
  0x10000: 'binds_to_weak',
  0x20000: 'allow_stack_execution',
  0x40000: 'root_safe',
  0x80000: 'setuid_safe',
  0x100000: 'reexported_dylibs',
  0x200000: 'pie',
  0x400000: 'dead_strippable_dylib',
  0x800000: 'has_tlv_descriptors',
  0x1000000: 'no_heap_execution'
};

Macho.cmdType = {
  0x80000000: 'req_dyld',
  0x1: 'segment',
  0x2: 'symtab',
  0x3: 'symseg',
  0x4: 'thread',
  0x5: 'unixthread',
  0x6: 'loadfvmlib',
  0x7: 'idfvmlib',
  0x8: 'ident',
  0x9: 'fmvfile',
  0xa: 'prepage',
  0xb: 'dysymtab',
  0xc: 'load_dylib',
  0xd: 'id_dylib',
  0xe: 'load_dylinker',
  0xf: 'id_dylinker',
  0x10: 'prebound_dylib',
  0x11: 'routines',
  0x12: 'sub_framework',
  0x13: 'sub_umbrella',
  0x14: 'sub_client',
  0x15: 'sub_library',
  0x16: 'twolevel_hints',
  0x17: 'prebind_cksum',

  0x80000018: 'load_weak_dylib',
  0x19: 'segment_64',
  0x1a: 'routines_64',
  0x1b: 'uuid',
  0x8000001c: 'rpath',
  0x1d: 'code_signature',
  0x1e: 'segment_split_info',
  0x8000001f: 'reexport_dylib',
  0x20: 'lazy_load_dylib',
  0x21: 'encryption_info',
  0x80000022: 'dyld_info',
  0x80000023: 'dyld_info_only',
  0x24: 'version_min_macosx',
  0x25: 'version_min_iphoneos',
  0x26: 'function_starts',
  0x27: 'dyld_environment',
  0x80000028: 'main',
  0x29: 'data_in_code',
  0x2a: 'source_version',
  0x2b: 'dylib_code_sign_drs',
  0x2c: 'encryption_info_64',
  0x2d: 'linker_option'
};

Macho.prot = {
	none: 0,
	read: 1,
	write: 2,
	execute: 4
};

Macho.segFlag = {
	1: 'highvm',
	2: 'fvmlib',
	4: 'noreloc',
	8: 'protected_version_1'
};

Macho.segTypeMask = 0xff;
Macho.segType = {
  0: 'regular',
  1: 'zerofill',
  2: 'cstring_literals',
  3: '4byte_literals',
  4: '8byte_literals',
  5: 'literal_pointers',
  6: 'non_lazy_symbol_pointers',
  7: 'lazy_symbol_pointers',
  8: 'symbol_stubs',
  9: 'mod_init_func_pointers',
  0xa: 'mod_term_func_pointers',
  0xb: 'coalesced',
  0xc: 'gb_zerofill',
  0xd: 'interposing',
  0xe: '16byte_literals',
  0xf: 'dtrace_dof',
  0x10: 'lazy_dylib_symbol_pointers',
  0x11: 'thread_local_regular',
  0x12: 'thread_local_zerofill',
  0x13: 'thread_local_variables',
  0x14: 'thread_local_variable_pointers',
  0x15: 'thread_local_init_function_pointers'
};

Macho.segAttrUsrMask = 0xff000000;
Macho.segAttrUsr = {
  '-2147483648': 'pure_instructions',
  0x40000000: 'no_toc',
  0x20000000: 'strip_static_syms',
  0x10000000: 'no_dead_strip',
  0x08000000: 'live_support',
  0x04000000: 'self_modifying_code',
  0x02000000: 'debug'
};

Macho.segAttrSysMask = 0x00ffff00;
Macho.segAttrSys = {
	0x400: 'some_instructions',
	0x200: 'ext_reloc',
	0x100: 'loc_reloc'
};

var Reader;

var MachoParser = function()
{
	if(!Reader)
	{
		Reader = new endianReader(); //Allocate an endianReader
	}
};

//Can download files from the internet
MachoParser.prototype.open = function open(file)
{
	var FileReader = new XMLHttpRequest();

	//Since we can not make CORS requests we need to use an API
	//The API is a PHP Script that will execute curl with using the http get url parameter as input
	FileReader.open('GET',"https://useafterfree.info/tools/fetch.php?url="+file, false);
	FileReader.overrideMimeType('text\/plain; charset=x-user-defined'); //Making sure that our content will be returned in plain text
	FileReader.send(null);

	//If we got a different status code from the API, a problem occured
	//200 means HTTP OK
	if(FileReader.responseCode != 200) {
		throw new Error('Unable to download file');
	}

	//Return the contents of the downloaded file
	return FileReader.responseText;
}


MachoParser.prototype.mapFlags = function mapFlags(value, map)
{
	var res = {};
	for(var bit = 1; (value < 0 || bit <= value) && bit !== 0; bit <<=1)
	{
		if(value & bit)
		{
			res[map[bit]] = true;
		}
	}
	return res;
}

MachoParser.prototype.ParseHead = function(buf)
{
	if(buf.length < 7 * 4)
	{
		throw new Error("Invalid filesize.");
		return false;
	}
	var magic = buf.readUInt32LE(0);
	var bits;

			//Little Endian 			//Big Endian
	if (magic === Macho.MH_MAGIC || magic === 0xcefaedfe)
		bits = 32; //32 bit MACHO-O file

			//Little Endian 			//Big Endian
	else if (magic === 0xfeedfacf || magic === 0xcffaedfe)
		bits = 64; //64-bit MACH-O file

	else
		console.log("Unexpected value while trying to read magic, got: "+magic + " /  0x"+magic.toString(16));
		return false; //Not a MACH-O file

	if (bits === 64 && buf.length < 8 * 4)
		return false; //truncated MACH-O header

	var cputype = Macho.cpuType[this.readInt32(buf, 4)];
	var cpusubType = this.readInt32(buf, 8);
	var filetype = this.readUInt32(buf, 12);
	var ncmds = this.readUint32(buf, 16);
	var sizeofcmds = this.readUint32(buf, 20);
	var flags = this.readUint32(buf, 24);

	var endian;
	if ((cpusubtype & Macho.endianness.multiple) === Macho.endianness.multiple)
    	endian = 'multiple';
	else if (cpusubtype & Macho.endianness.be)
	    endian = 'big_endian';
	else
		endian = 'little_endian';
	cpusubtype &= Macho.cpuSubType.mask;
	
	var subtype;
	if (endian === 'multiple')
	    subtype = 'all';
	else if (cpusubtype === 0)
	    subtype = 'none';
	else
	    subtype = constants.cpuSubType[cputype][cpusubtype];
	var flagMap = this.mapFlags(flags, Macho.flags);
	return {
		bits: bits,
		magic: magic,
		cpu: {
			type: cpu,
			subtype: subtype,
			endian: endian,
		},
		fileType: Macho.fileType[filetype],
		ncmds: ncmds,
		sizeofcmds: sizeofcmds,
		flags: flagMap,
		cmds: null,
		hsize: bits === 32 ? 28 : 32,
		body: bits === 32 ? buf.slice(28) : buf.slice(32)
	};
};

MachoParser.prototype.execute = function execute(buf)
{
	var header = this.ParseHead(buf);
	if(!header)
	{
		//We were unable to detect the Macho Header
		throw new Error('Not a MACH-O File.');
	}
	header.cmds = MachoParser.parseCommands(header, header.body, buf);
	header.body = undefined;
	return header;
};

MachoParser.prototype.parseCommands = function parseCommands(mh_header, buf, size)
{
	var cmds = [];
	var align;
	if(mh_header.bits === 32)
		align = 4;
	else
		align = 8;
	for (var offset = 0, i = 0; offset + 8 < buf.length, i < mh_header.ncmds; i++)
	{
		var type = Macho.cmdType[buf.readUint32(offset)];
		var size = buf.readUInt32(buf, offset + 4) - 8;
		var fileoff = offset + mh_header.hsize;
		offset += 8;
		if (offset + size > buf.length)
			throw new Error('Command body OOB');
		var body = buf.slice(offset, offset + size);
		offset += size;
		if (offset & align)
			offset += align - (offset & align);
		var cmd = this.parseCommand(type, body, file);
		cmd.fileoff = fileoff;
		cmds.push(cmd);
	}
	return cmds;
};

MachoParser.prototype.parseCStr = function parseCStr(buf)
{
	for(var i = 0; i < buf.length; i++)
		if(buf[i] === 0)
			break;
	return buf.slice(0, i).toString();
};

MachoParser.prototype.parseLCStr = function parseLCStr(buf, off)
{
	if( off + 4 > buf.length)
		throw new Error('lc_str OOB');
	return MachoParser.parseCStr(buf.slice(offset));
}

MachoParser.prototype.parseCommand = function parseCommand(type, buf, file)
{
	if(type === 'segment')
		return MachoParser.parseSegmentCmd(type, buf, file);
	else if (type === 'segment_64')
		return MachoParser.parseSegmentCmd(type, buf, file);
	else if (type === 'symtab')
		return MachoParser.parseSymtab(type, buf);
	else if (type === 'symseg')
		return MachoParser.parseSymseg(type, buf);
	 else if (type === 'encryption_info')
    	return MachoParser.parseEncryptionInfo(type, buf);
	else if (type === 'encryption_info_64')
		return MachoParser.parseEncryptionInfo64(type, buf);
	else if (type === 'rpath')
		return MachoParser.parseRpath(type, buf);
	else if (type === 'dysymtab')
		return MachoParser.parseDysymtab(type, buf);
	else if (type === 'load_dylib' || type === 'id_dylib')
		return MachoParser.parseLoadDylib(type, buf);
	else if (type === 'load_weak_dylib')
		return MachoParser.parseLoadDylib(type, buf);
	else if (type === 'load_dylinker' || type === 'id_dylinker')
		return MachoParser.parseLoadDylinker(type, buf);
	else if (type === 'version_min_macosx' || type === 'version_min_iphoneos')
		return MachoParser.parseVersionMin(type, buf);
	else if (type === 'code_signature' || type === 'segment_split_info')
		return MachoParser.parseLinkEdit(type, buf);
	else if (type === 'function_starts')
		return MachoParser.parseFunctionStarts(type, buf, file);
	else if (type === 'data_in_code')
		return MachoParser.parseLinkEdit(type, buf);
	else if (type === 'dylib_code_sign_drs')
		return MachoParser.parseLinkEdit(type, buf);
	else if (type === 'main')
		return MachoParser.parseMain(type, buf);
	else
		return { type: type, data: buf };
};

MachoParser.prototype.parseSegmentCmd = function parseSegmentCmd(type, buf, file) {
	var total = type === 'segment' ? 48 : 64;
	if (buf.length < total)
		throw new Error('Segment command OOB');

	var name = this.parseCStr(buf.slice(0, 16));

	if (type === 'segment') {
		var vmaddr = this.readUInt32(buf, 16);
		var vmsize = this.readUInt32(buf, 20);
		var fileoff = this.readUInt32(buf, 24);
		var filesize = this.readUInt32(buf, 28);
		var maxprot = this.readUInt32(buf, 32);
		var initprot = this.readUInt32(buf, 36);
		var nsects = this.readUInt32(buf, 40);
		var flags = this.readUInt32(buf, 44);
	} else {
		var vmaddr = this.readUInt64(buf, 16);
		var vmsize = this.readUInt64(buf, 24);
		var fileoff = this.readUInt64(buf, 32);
		var filesize = this.readUInt64(buf, 40);
		var maxprot = this.readUInt32(buf, 48);
		var initprot = this.readUInt32(buf, 52);
		var nsects = this.readUInt32(buf, 56);
		var flags = this.readUInt32(buf, 60);
	}
	function prot(p) {
    	var res = { read: false, write: false, exec: false };
    	if (p !== Macho.prot.none) {
      		res.read = (p & Macho.prot.read) !== 0;
      		res.write = (p & Macho.prot.write) !== 0;
      		res.exec = (p & Macho.prot.execute) !== 0;
    	}
    	return res;
	 }
  	var sectSize = type === 'segment' ? 32 + 9 * 4 : 32 + 8 * 4 + 2 * 8;
  	var sections = [];
  	for (var i = 0, off = total; i < nsects; i++, off += sectSize) {
 	   if (off + sectSize > buf.length)
 	     throw new Error('Segment OOB');

 	   var sectname = this.parseCStr(buf.slice(off, off + 16));
 	   var segname = this.parseCStr(buf.slice(off + 16, off + 32));

 	   if (type === 'segment') {
	    	var addr = this.readUInt32(buf, off + 32);
	    	var size = this.readUInt32(buf, off + 36);
	    	var offset = this.readUInt32(buf, off + 40);
 	    	var align = this.readUInt32(buf, off + 44);
	    	var reloff = this.readUInt32(buf, off + 48);
	    	var nreloc = this.readUInt32(buf, off + 52);
	    	var flags = this.readUInt32(buf, off + 56);
    	} else {
      		var addr = this.readUInt64(buf, off + 32);
	      	var size = this.readUInt64(buf, off + 40);
	      	var offset = this.readUInt32(buf, off + 48);
	      	var align = this.readUInt32(buf, off + 52);
	      	var reloff = this.readUInt32(buf, off + 56);
	      	var nreloc = this.readUInt32(buf, off + 60);
	      	var flags = this.readUInt32(buf, off + 64);
    	}
	    sections.push({
	      sectname: sectname,
	      segname: segname,
	      addr: addr,
	      size: size,
	      offset: offset,
	      align: align,
	      reloff: reloff,
	      nreloc: nreloc,
	      type: Macho.segType[flags & Macho.segTypeMask],
	      attributes: {
	        usr: this.mapFlags(flags & Macho.segAttrUsrMask,
	                           Macho.segAttrUsr),
	        sys: this.mapFlags(flags & Macho.segAttrSysMask,
	                           Macho.segAttrSys)
	      },
	      data: file.slice(offset, offset + size)
	    });
	  }

  return {
    type: type,
    name: name,
    vmaddr: vmaddr,
    vmsize: vmsize,
    fileoff: fileoff,
    filesize: filesize,
    maxprot: prot(maxprot),
    initprot: prot(initprot),
    nsects: nsects,
    flags: this.mapFlags(flags, Macho.segFlag),
    sections: sections
  };
};

MachoParser.prototype.parseSymtab = function parseSymtab(type, buf) {
  if (buf.length !== 16)
    throw new Error('symtab OOB');

  return {
    type: type,
    symoff: this.readUInt32(buf, 0),
    nsyms: this.readUInt32(buf, 4),
    stroff: this.readUInt32(buf, 8),
    strsize: this.readUInt32(buf, 12)
  };
};

MachoParser.prototype.parseSymseg = function parseSymseg(type, buf) {
  if (buf.length !== 8)
    throw new Error('symseg OOB');

  return {
    type: type,
    offset: this.readUInt32(buf, 0),
    size: this.readUInt32(buf, 4)
  };
};

MachoParser.prototype.parseEncryptionInfo = function parseEncryptionInfo(type, buf) {
  if (buf.length !== 12)
    throw new Error('encryptinfo OOB');

  return {
    type: type,
    offset: this.readUInt32(buf, 0),
    size: this.readUInt32(buf, 4),
    id: this.readUInt32(buf, 8),
  };
};

MachoParser.prototype.parseEncryptionInfo64 = function parseEncryptionInfo64(type, buf) {
  if (buf.length !== 16)
    throw new Error('encryptinfo64 OOB');

  return this.parseEncryptionInfo(type, buf.slice(0, 12));
};

MachoParser.prototype.parseDysymtab = function parseDysymtab(type, buf) {
  if (buf.length !== 72)
    throw new Error('dysymtab OOB');

  return {
    type: type,
    ilocalsym: this.readUInt32(buf, 0),
    nlocalsym: this.readUInt32(buf, 4),
    iextdefsym: this.readUInt32(buf, 8),
    nextdefsym: this.readUInt32(buf, 12),
    iundefsym: this.readUInt32(buf, 16),
    nundefsym: this.readUInt32(buf, 20),
    tocoff: this.readUInt32(buf, 24),
    ntoc: this.readUInt32(buf, 28),
    modtaboff: this.readUInt32(buf, 32),
    nmodtab: this.readUInt32(buf, 36),
    extrefsymoff: this.readUInt32(buf, 40),
    nextrefsyms: this.readUInt32(buf, 44),
    indirectsymoff: this.readUInt32(buf, 48),
    nindirectsyms: this.readUInt32(buf, 52),
    extreloff: this.readUInt32(buf, 56),
    nextrel: this.readUInt32(buf, 60),
    locreloff: this.readUInt32(buf, 64),
    nlocrel: this.readUInt32(buf, 68)
  };
};

MachoParser.prototype.parseLoadDylinker = function parseLoadDylinker(type, buf) {
  return {
    type: type,
    cmd: this.parseLCStr(buf, 0)
  };
};

MachoParser.prototype.parseRpath = function parseRpath (type, buf) {
  if (buf.length < 8)
    throw new Error('lc_rpath OOB');

  return {
    type: type,
    name: this.parseLCStr(buf, 0),
  };
};

MachoParser.prototype.parseLoadDylib = function parseLoadDylib(type, buf) {
  if (buf.length < 16)
    throw new Error('load_dylib OOB');

  return {
    type: type,
    name: this.parseLCStr(buf, 0),
    timestamp: this.readUInt32(buf, 4),
    current_version: this.readUInt32(buf, 8),
    compatibility_version: this.readUInt32(buf, 12)
  };
};

MachoParser.prototype.parseVersionMin = function parseVersionMin(type, buf) {
  if (buf.length !== 8)
    throw new Error('min version OOB');

  return {
    type: type,
    version: this.readUInt16(buf, 2) + '.' + buf[1] + '.' + buf[0],
    sdk: this.readUInt16(buf, 6) + '.' + buf[5] + '.' + buf[4]
  };
};

MachoParser.prototype.parseLinkEdit = function parseLinkEdit(type, buf) {
  if (buf.length !== 8)
    throw new Error('link_edit OOB');

  return {
    type: type,
    dataoff: this.readUInt32(buf, 0),
    datasize: this.readUInt32(buf, 4)
  };
};

MachoParser.prototype.parseFunctionStarts = function parseFunctionStarts(type,
                                                                    buf,
                                                                    file) {
  if (buf.length !== 8)
    throw new Error('function_starts OOB');

  var dataoff = this.readUInt32(buf, 0);
  var datasize = this.readUInt32(buf, 4);
  var data = file.slice(dataoff, dataoff + datasize);

  var addresses = [];
  var address = 0;

  // read array of uleb128-encoded deltas
  var delta = 0, shift = 0;
  for (var i = 0; i < data.length; i++) {
    delta |= (data[i] & 0x7f) << shift;
    if ((data[i] & 0x80) !== 0) { // delta value not finished yet
      shift += 7;
      if (shift > 24)
        throw new Error('function_starts delta too large');
      else if (i + 1 === data.length)
        throw new Error('function_starts delta truncated');
    } else if (delta === 0) { // end of table
      break;
    } else {
      address += delta;
      addresses.push(address);
      delta = 0;
      shift = 0;
    }
  }

  return {
    type: type,
    dataoff: dataoff,
    datasize: datasize,
    addresses: addresses
  };
};

MachoParser.prototype.parseMain = function parseMain(type, buf) {
  if (buf.length < 16)
    throw new Error('main OOB');

  return {
    type: type,
    entryoff: this.readUInt64(buf, 0),
    stacksize: this.readUInt64(buf, 8)
  };
};


var Program = new Object();
Program.Run = function Run(machofile)
{
	var Runtime = new Object();
	Runtime.macho = Macho;
	Runtime.Parser = new MachoParser();

	var FILE = Runtime.Parser.open(machofile);
	FILE = buffer.Buffer.from(FILE);
	return Runtime.Parser.execute(FILE);
}

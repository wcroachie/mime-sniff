function mimeSniff(blob){
  
  function arrayBufferToHexBytes(buff){
    return [...new Uint8Array(buff)].map(e=>e.toString(16).padStart(2,0));
  }
  
  // get first 4096 bytes
  var hexbytes  = arrayBufferToHexBytes(blob.slice(0,4096).toArrayBuffer());
  var chars     = hexbytes.map(e=>String.fromCharCode(parseInt(e,16)));
  var header    = chars.join("");
  
  // use this to check if the file is likely plaintext or binary
  function isBinaryString(str){
    // https://mimesniff.spec.whatwg.org/#binary-data-byte
    // A binary data byte is a byte in the ranges:
    // 0x00 to 0x08 (NUL to BS),
    // the byte 0x0B (VT),
    // a byte in the range 0x0E to 0x1A (SO to SUB) (14 to 26),
    // or a byte in the range 0x1C to 0x1F (FS to US) (28 to 31).
    var BINARY_MATCH_TEST = /\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x0B|\x0E|\x0F|\x11|\x12|\x13|\x14|\x15|\x16|\x17|\x18|\x19|\x1A|\x1C|\x1D|\x1E|\x1F/;
    return !!BINARY_MATCH_TEST.test(str)
  }
  
  return !isBinaryString(header) ? function handlePlaintextFiles(){
    // what kind of plaintext file is it?
    var trimmed = header.trim();
    switch(true){
      /* byte order marks */
      case header.startsWith("\xFE\xFF")      :return ["txt","text/plain; charset=utf-16be"];
      case header.startsWith("\xFF\xFE")      :return ["txt","text/plain; charset=utf-16le"];
      case header.startsWith("\xEF\xBB\xBF")  :return ["txt","text/plain; charset=utf-8"];
      /* obj file */
      case /^(\#(.*?)\n|v\s([-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?\.?)\s([-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?\.?)\s([-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?\.?)\n)/s.test(header):return ["obj","model/obj"];
      /* html, xml, or svg... */
      case trimmed.startsWith("<"):
        // get rid of a comment if it exists before the start of the file
        trimmed = trimmed.toLowerCase().replaceAll("\n","").replace(/^<!--(.*?)-->/s);
        switch(true){
          case trimmed.startsWith("<?xml"):
            // which kind of xml?
            switch(true){
              case /\<feed/.test(trimmed) :return ["rss","application/atom+xml"];
              case /\<rss/.test(trimmed)  :return ["rss","application/atom+xml"];
              case /\<svg/.test(trimmed)  :return ["svg","image/svg+xml"]; // while rare, could just be xml file containing an svg? need to be more precise about this
              default : return "text/xml";
            }
          case trimmed.startsWith("<svg")           :return ["svg","image/svg+xml"];
          case trimmed.startsWith("<!doctype svg")  :return ["svg","image/svg+xml"];
          case trimmed.startsWith("<!doctype html") :return ["html","text/html"];
        }
      /* json? */
      case trimmed.startsWith("{") :
        /**
         * @todo - probably json? mask out illegal syntax in json here
        */
        return ["json","application/json"];
      /* other ones... */
      /**
       * @todo - otherwise see if js, css, py, c, cc, h, etc
      */
      /* default to texp/plaim */
      default : return ["txt","text/plain"];
    }
  }() : function handleBinaryFiles(){
    // what kind of binary file is it?
    switch(true){

      case /^7z\xBC\xAF\x27\x1C/s.test(header)    : return ["7z","application/x-7z-compressed"];
      // test for apng, must come before png check
      case /^\x89PNG\x0D\x0A\x1A\x0A(.*?)acTL(.*?)IDAT/s.test(header) : return ["apng","image/apng"];
      case /^\x89PNG\x0D\x0A\x1A\x0A/.test(header)                    : return ["png","image/png"];
      case /^\x67\x6C\x54\x46\x02\x00\x00\x00/s.test(header)          : return ["glb","model/gltf-binary"];
      case /^\x4F\x54\x54\x4F\x00/s.test(header)                      : return ["otf","font/otf"];
      case /^IMPM/s.test(header)                                      : return ["it","audio/x-it"];
      case /^....free/s.test(header)                : return ["mov","video/quicktime"];
      case /^....mdat/s.test(header)                : return ["mov","video/quicktime"]; // MJPEG
      case /^....moov/s.test(header)                : return ["mov","video/quicktime"];
      case /^....wide/s.test(header)                : return ["mov","video/quicktime"];
      case /^\x00\x00\x01\xBA\x21/s.test(header)    : return ["mpg","video/MP1S"]; // {offset: 4, mask: [\xF1]} //  MPEG-PS, MPEG-1 Part 1 // May also be .ps, .mpeg
      case /^\x00\x00\x01\xBA\x44/s.test(header)    : return ["mpg","video/MP2P"];  // {offset: 4, mask: [\xC4]} // MPEG-PS, MPEG-2 Part 1 // May also be .mpg, .m2p, .vob or .sub
      case /^\x00\x00\x01(\xBA|\xB3)/s.test(header) : return ["mpg","video/mpeg"];
      case /^\x00\x01\x00\x00\x00/s.test(header)    : return ["ttf","font/ttf"];
      case /^\x47.{187}\x47/s.test(header)          : return ["mts","video/mp2t"]; // Raw MPEG-2 transport stream (188-byte packets)
      case /^....\x47.{191}\x47/s.test(header)      : return ["mts","video/mp2t"]; // Blu-ray Disc Audio-Video (BDAV) MPEG-2 transport stream has 4-byte TP_extra_header before each 188-byte packet
      case /^\xAB\x4B\x54\x58\x20\x31\x31\xBB\x0D\x0A\x1A\x0A/s.test(header) : return ["ktx","image/ktx"];
      // bruh i have no idea what most of these even are and they havent been tested and probably never will be but what the fuck ever
      case /^\xED\xAB\xEE\xDB/s.test(header)    : return ["rpm","application/x-rpm"];
      case /^\xC5\xD0\xD3\xC6/s.test(header)    : return ["eps","application/eps"];
      case /^\x28\xB5\x2F\xFD/s.test(header)    : return ["zst","application/zstd"];
      case /^\x7F\x45\x4C\x46/s.test(header)    : return ["elf","application/x-elf"];
      case /^\x21\x42\x44\x4E/s.test(header)    : return ["pst","application/vnd.ms-outlook"];
      case /^PAR1/s.test(header)                : return ["parquet","application/x-parquet"];
      case /^\x0B\x77/s.test(header)            : return ["ac3","audio/vnd.dolby.dd-raw"];
      case /^\x78\x01/s.test(header)            : return ["dmg","application/x-apple-diskimage"];
      case /^MZ/s.test(header)                  : return ["exe","application/x-msdownload"];
      case /^\%\!PS\-Adobe\-.. EPSF\-/s.test(header) : return ["eps","application/eps"];
      case /^\%\!PS\-Adobe\-/s.test(header)     : return ["ps","application/postscript"];
      case /^\%PDF\-/s.test(header)             : return ["pdf","application/pdf"];
      case /^\%PDF/s.test(header)               : return ["pdf","application/pdf"];
      case /^(\x1F\xA0|\x1F\x9D)/s.test(header) : return ["z","application/x-compress"];
      case /^GIF/s.test(header)                 : return ["gif","image/gif"];
      case /^(\x43|\x46)\x57\x53/s.test(header) : return ["swf","application/x-shockwave-flash"];
      case /^\x49\x49\xBC/s.test(header)        : return ["jxr","image/vnd.ms-photo"];
      case /^\x42\x5A\x68/s.test(header)        : return ["bz2","application/x-bzip2"];
      case /^MP\+/s.test(header)                : return ["mpc","audio/x-musepack"];
      case /^\xFF\xD8\xFF\xF7/s.test(header)    : return ["jls","image/jls"];   // JPG7/SOF55, indicating a ISO/IEC 14495 / JPEG-LS file
      case /^FLIF/s.test(header)                : return ["flif","image/flif"];
      case /^8BPS/s.test(header)                : return ["psd","image/vnd.adobe.photoshop"];
      case /^........WEBP/s.test(header)        : return ["webp","image/webp"];
      case /^MPCK/s.test(header)                : return ["mpc","audio/x-musepack"]; // Musepack, SV8
      case /^FORM/s.test(header)                : return ["aif","audio/aiff"];
      case /^icns/s.test(header)                : return ["icns","image/icns"];
      /**
       * @todo - handle zip-like files here
      */
      /* couldnt find way to distinguish between these yet (most methods i found like gary kessler's dont seem to work) */
      // case /^\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1/s.test(header) : return ["doc | ppt | xls","application/msword | application/vnd.ms-powerpoint | application/vnd.ms-excel"];        
      /* couldnt find way to distinguish between these yet (same as above, i havent found a surefire method yet)*/
      // case /^PK\x03\x04/s.test(header) : return ["docx | pptx | xlsx","application/vnd.openxmlformats-officedocument.wordprocessingml.document | application/vnd.openxmlformats-officedocument.presentationml.presentation | vnd.openxmlformats-officedocument.spreadsheetml.sheet"];
      case /^PK\x03\x04.{32}\x70\x65\x61\x70\x70\x6C\x69\x63\x61\x74\x69\x6F\x6E\x2F\x65\x70\x75\x62\x2B\x7A\x69\x70/s.test(header) : return ["epub","application/epub+zip"];
      case /^PK\x03\x04(.*?)mimetype(.*?)application\/x\-krita/s.test(header): return ["kra","application/x-krita"];
      case /^PK\x03\x04(.*?)(\/([-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?\.?)\~([-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?\.?)\.chunk|QuickLook\/Thumbnail\.png(.*?)Document\.archive)/s.test(header): return ["procreate","application/x-procreate"];
      case /^PK(\x03|\x05|\x07)(\x04|\x06|\x08)/s.test(header)        : return ["zip","application/x-zip-compressed"];
      case /^CSFCHUNK\x00\x00/s.test(header)                          : return ["clip","application/x-clip-studio"];
      case /^OggS........................OpusHead/s.test(header)      : return ["opus","audio/opus"];
      case /^OggS........................\x80theora/s.test(header)    : return ["ogv","video/ogg"];
      case /^OggS........................\x01video\x00/s.test(header) : return ["ogm","video/ogg"];
      case /^OggS........................\x7FFLAC/s.test(header)      : return ["oga","audio/ogg"];
      case /^OggS........................Speex\x20\x20/s.test(header) : return ["spx","audio/ogg"];
      case /^OggS........................\x01vorbis/s.test(header)    : return ["ogg","audio/ogg"];
      case /^OggS/s.test(header)                                      : return ["ogx","application/ogg"];
      case /^MThd/s.test(header)                                      : return ["mid","audio/midi"];
      case /^\x1a\x45\xdf\xa3(.*?)\x42\x82.matroska/s.test(header)    : return ["mkv","video/x-matroska"];
      case /^\x1a\x45\xdf\xa3(.*?)\x42\x82.webm/s.test(header)        : return ["webm","video/webm"];
      case /^\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9/s.test(header)  :
        if(
             /.{10}\x40\x9E\x69\xF8\x4D\x5B\xCF\x11\xA8\xFD\x00\x80\x5F\x5C\x44\x2C/s.test(header)
          && /.{10}\xC0\xEF\x19\xBC\x4D\x5B\xCF\x11\xA8\xFD\x00\x80\x5F\x5C\x44\x2B/s.test(header)
        ){
          return ["wmv","video/x-ms-asf"];
        }else if(/.{10}\x40\x9E\x69\xF8\x4D\x5B\xCF\x11\xA8\xFD\x00\x80\x5F\x5C\x44\x2B/s.test(header)){
          return ["wma","audio/x-ms-wma"];
        }else if(/.{10}\xC0\xEF\x19\xBC\x4D\x5B\xCF\x11\xA8\xFD\x00\x80\x5F\x5C\x44\x2B/s.test(header)){
          return ["wmv","video/x-ms-wmv"];
        }else{
          return ["asf","application/vnd.ms-asf"]
        }
      case /^....ftypavi(f|s)/s.test(header)    : return ["avif","image/avif"];
      case /^....ftypmif1/s.test(header)        : return ["heic","image/heif"];
      case /^....ftypmsf1/s.test(header)        : return ["heic","image/heif-sequence"];
      case /^....ftyphei(c|x)/s.test(header)    : return ["heic","image/heic"];
      case /^....ftyphev(c|x)/s.test(header)    : return ["heic","image/heic-sequence"];
      case /^....ftypqt/s.test(header)          : return ["mov","video/quicktime"];
      case /^....ftypM4V.....M4V\x20M4A\x20/s.test(header) : return["mp4","video/mp4"]; // m4v+m4a
      case /^....ftypM4V((H|P)?)/s.test(header) : return ["m4v","video/x-m4v"];
      case /^....ftypM4P/s.test(header)         : return ["m4p","audio/mp4a-latm"]; // itunes audio. yes it is m4p, do not mistype as  mp4
      case /^....ftypM4B/s.test(header)         : return ["m4b","audio/mp4a-latm"]; // itunes audio book
      case /^....ftypM4A/s.test(header)         : return ["m4a","audio/x-m4a"];
      case /^....ftypF4V/s.test(header)         : return ["f4v","video/mp4"];
      case /^....ftypF4P/s.test(header)         : return ["f4p","video/mp4"];
      case /^....ftypF4A/s.test(header)         : return ["f4a","audio/mp4"];
      case /^....ftypF4B/s.test(header)         : return ["f4b","audio/mp4"];
      case /^....ftypcrx/s.test(header)         : return ["cr3","image/x-canon-cr3"];
      case /^....ftyp3g2/s.test(header)         : return ["3g2","video/3gpp2"];
      case /^....ftyp3g/s.test(header)          : return ["3gp","video/3gpp"];
      case /^....ftyp(mp41|mp42|isom|iso2|mmp4|dash)/s.test(header) : return ["mp4","video/mp4"];
      case /^....ftyp3g/s.test(header)          : return ["3gp","video/3gpp"];
      case /^....ftypavcl/s.test(header)        : return ["3gp","video/3gpp"];
      case /^....ftyp/s.test(header)            : return ["mpeg","application/mpeg"]; // otherwise some application of mpeg
      case /^....moov/s.test(header)            : return ["mov","video/quicktime"];
      case /^3gp5/s.test(header)                : return ["mp4","video/mp4"]; // not sure about this one
      case /^\x00\x00\x00\x0C\x6A\x50\x20\x20\x0d\x0A\x87\x0A/s.test(header) : 
        if(/^.{20}\x6A\x70\x32\x20/s.test(header)){
          return ["jp2","image/jp2"];
        }else if(/^.{20}\x6A\x70\x78\x20/s.test(header)){
          return ["jpx","image/jpx"];
        }else if(/^.{20}\x6A\x70\x6D\x20/s.test(header)){
          return ["jpm","image/jpm"];
        }else if(/^.{20}\x6D\x6A\x70\x32/s.test(header)){
          return ["mj2","image/mj2"];
        }
      case /^ID3/s.test(header) : return ["mp3","audio/mpeg"]; // mp3 with id3 container
      case /^\xFF(\xE2|\xE3|\xF2|\xF3|\xFA|\xFB)/s.test(header): return["mp3","audio/mpeg"];
      case /^\xFF(\xE4|\xE5|\xF4|\xF5|\xFC|\xFD)/s.test(header): return["mp2","audio/mpeg"];
      case /^\xFF(\xE6|\xE7|\xF6|\xF7|\xFE|\xFF)/s.test(header): return["mp1","audio/mpeg"];
      // these were found by me through testing but i still cant discern the patterns here... im not smart enough
      case /^\xC2\x0E/s.test(header): return["mp1","audio/mpeg"];
      case /^\xC2\xC1/s.test(header): return["mp1","audio/mpeg"];
      case /^\xC2\xD6/s.test(header): return["mp1","audio/mpeg"];
      case /^\xC4\x7B/s.test(header): return["mp1","audio/mpeg"];
      case /^\xC8\x93/s.test(header): return["mp1","audio/mpeg"];
      case /^\xE4\x0F/s.test(header): return["mp1","audio/mpeg"];
      // from gary kessler's list
      case /^\xFF\xF1/s.test(header): return["aac","audio/aac"] // MPEG-4 Advanced Audio Coding (AAC) Low Complexity (LC) audio file
      case /^\xFF\xF9/s.test(header): return["aac","audio/aac"]// MPEG-2 Advanced Audio Coding (AAC) Low Complexity (LC) audio file
      // https://en.wikipedia.org/wiki/List_of_file_signatures
      case /^\xFF(\xFB|\xF3|\xF2)/s.test(header) : return ["mp3","audio/mpeg"]; // MPEG-1 Layer 3 file without an ID3 tag or with an ID3v1 tag (which is appended at the end of the file)
      case /^\xFF(\xF0|\xF1|\xF2|\xF3|\xF4|\xF5|\xF6|\xF7|\xF8|\xF9|\xFA|\xFB|\xFC|\xFD|\xFE|\xFF)/s.test(header) : return ["mpga","audio/mpeg"];
      case /^\xFF(\xE0|\xE1|\xE2|\xE3|\xE4|\xE5|\xE6|\xE7|\xE8|\xE9|\xEA|\xEB|\xEC|\xED|\xEE|\xEF)/s.test(header) : return ["mpga","audio/mpeg"];
      case /^wOFF(\x00\x01\x00\x00|OTTO)/s.test(header)         : return ["woff","font/woff"];
      case /^wOF2(\x00\x01\x00\x00|OTTO)/s.test(header)         : return ["woff2","font/woff2"];
      case /^(\xD4\xC3\xB2\xA1|\xA1\xB2\xC3\xD4)/s.test(header) : return ["pcap","application/vnd.tcpdump.pcap"];
      case /^DSD\s/s.test(header)                               : return ["dsf","audio/x-dsf"]; // Sony DSD Stream File (DSF) (Non-standard mime)
      case /^LZIP/s.test(header)              : return ["lz","application/x-lzip"];
      case /^fLaC/s.test(header)              : return ["flac","audio/x-flac"];
      case /^\x42\x50\x47\xFB/s.test(header)  : return ["bpg","image/bpg"];
      case /^wvpk/s.test(header)              : return ["wv","audio/wavpack"];
      case /^\x00\x61\x73\x6D/s.test(header)  : return ["wasm","application/wasm"];
      case /^MAC\s/s.test(header)             : return ["ape","audio/ape"];
      case /^SQLi/s.test(header)              : return ["sqlite","application/x-sqlite3"];
      case /^Cr24/s.test(header)              : return ["crx","application/x-google-chrome-extension"];
      case /^(MSCF|ISc\()/s.test(header)      : return ["cab","application/vnd.ms-cab-compressed"];
      case /^\xFF\xD8\xFF/s.test(header)            : return ["jpeg","image/jpeg"];
      case /^BM/.test(header)                       : return ["bmp","image/bmp"];
      case /^\x1F\x8B\x08/s.test(header)            : return ["gz","application/gzip"];
      case /^\x2E\x52\x4D\x46/s.test(header)        : return ["rmp","audio/x-pn-realaudio"];
      case /^\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C/s.test(header) : return ["asf","video/x-ms-asf"]
      case /^I\sI/s.test(header)              : return ["tiff","image/tiff"];
      case /^II\*/s.test(header)              : return ["tiff","image/tiff"];
      case /^MM\x00\*/s.test(header)          : return ["tiff","image/tiff"];
      case /^RIFF....WEBPVP/s.test(header)    : return ["webp","image/webp"];
      case /^Rar\!\x1A\x07\x00/s.test(header) : return ["rar","application/x-rar-compressed"];
      case /^\xD7\xCD\xC6\x9A/s.test(header)  : return ["wmf","application/x-msmetafile"];
      case /^(CWS|FWS)/.test(header)          : return ["swf","application/x-shockwave-flash"];
      case /^FLV/s.test(header)               : return ["flv","video/x-flv"];
      case /^\#define/s.test(header)          : return ["xbm","image/x-xbitmap"];
      case /^RIFF....WAVEfmt\s/s.test(header) : return ["wav","audio/wav"];
      case /^RIFF....AVI\sLIST/s.test(header) : return ["avi","video/avi"];  
      case /^\#\!AMR\n/s.test(header)                     : return ["amr","audio/amr"];
      case /^II\x2a\x00\x10\x00\x00\x00CR/s.test(header)  : return ["cr2","image/x-canon-cr2"];
      case /^II\x1a\x00\x00\x00HEAPCCDR/s.test(header)    : return ["crw","image/x-canon-crw"];
      case /^\x00MRM/s.test(header)                       : return ["mrw","image/x-minolta-mrw"];
      case /^MMOR/s.test(header)                          : return ["orf","image/x-olympus-orf"]; // big endian
      case /^IIRO/s.test(header)                          : return ["orf","image/x-olympus-orf"]; // little endian
      case /^IIRS/s.test(header)                          : return ["orf","image/x-olympus-orf"]; // little endian
      case /^FUJIFILMCCD-RAW\s/s.test(header)             : return ["raf","image/x-fuji-raf"];
      case /^IIU\x00\x08\x00\x00\x00/s.test(header)       : return ["raw","image/x-panasonic-raw"]; // Panasonic .raw
      case /^IIU\x00\x18\x00\x00\x00/s.test(header)       : return ["rw2","image/x-panasonic-raw"]; // Panasonic .rw2
      case /^MMMMRaw/s.test(header)                       : return ["iiq","image/x-phaseone-raw"];
      case /^FOVb/s.test(header)                          : return ["x3f","image/x-x3f"];
      case /^BLENDER/s.test(header)                       : return ["blend","application/x-blender"];
      case /^\{\\rtf/s.test(header)                       : return ["rtf","application/rtf"];
      case /^\x4E\x45\x53\x1A/s.test(header)              : return ["nes","application/x-nintendo-nes-rom"];
      case /^\x67\x6c\x54\x46\x02\x00\x00\x00/s.test(header) : ["glb","model/gltf-binary"];
      case /^\x00\x00\x02\x00/s.test(header)              : return ["cur","image/x-icon"]; // cur file
      case /^\x00\x00\x01\x00/s.test(header)              : return ["ico","image/x-icon"]; // ico file

      default : return ["bin","application/octet-stream"];
    }
  }()
}

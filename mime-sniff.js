/**
 * 
 * sniff-mime.js v02 - 8/27/23 - wcroachie
 * 
 * this tool can be used to sniff the mimetype
 * of binary data for a file where the mime is
 * not known or trusted
 * 
 * due to the huge amount of work involved irt
 * keeping track of all mime types and their
 * magic numbers as well as conflicts, aliases,
 * and other stuff - consider this a tool to help
 * decide the most likely mime but not watertight
 * in any capacity
 * 
 * sources/further reading:
 *    https://en.wikipedia.org/wiki/List_of_file_signatures
 *    https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types
 *    https://www.garykessler.net/library/file_sigs.html
 * 
 * @param {[object Blob]} blob a blob
 * @returns {string} a string containing the mime type
 */

function sniffMime( blob ){

  /** 
   * determines if the input contains "binary" characters
   * 
   * https://mimesniff.spec.whatwg.org/#binary-data-byte
   * 
   *  "...binary data byte is a byte in the ranges:
   *  - 0x00 to 0x08 (NUL to BS),
   *  - the byte 0x0B (VT),
   *  - a byte in the range 0x0E to 0x1A (SO to SUB) (14 to 26),
   *  - or a byte in the range 0x1C to 0x1F (FS to US) (28 to 31)..."
   * 
   * @param {string} str a string
   * @returns {boolean} true or false
   * 
  */
  function isBinary( str ){
    return /\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x0B|\x0E|\x0F|\x11|\x12|\x13|\x14|\x15|\x16|\x17|\x18|\x19|\x1A|\x1C|\x1D|\x1E|\x1F/.test(str);
  }

  function str2ui8(str){
    return new Uint8Array( str.split("").map( e => e.codePointAt() ) );
  }

  function blob2xhrSync( blob ){
    var url = URL.createObjectURL( blob );
    var req = new XMLHttpRequest();
    req.open( "GET", url, false );
    req.overrideMimeType( "text/plain; charset=x-user-defined" );
    req.send();
    URL.revokeObjectURL( url );
    return req;
  }

  function blob2ui8( blob ){
    var req = blob2xhrSync( blob );
    var text = req.response;
    return str2ui8(text);
  }

  var header = [ ...blob2ui8(blob.slice(0,4096)) ].map( e=>String.fromCodePoint(e) ).join("");
  var trailer = [ ...blob2ui8(blob.slice(-4096)) ].map( e=>String.fromCodePoint(e) ).join("");

  console.log(header);

  /**
   * sometimes, long pdfs will not show a binary
   * character in the header, so consider them
   * as potentially being flagged as both binary
   * or plaintext
   * 
   * same with .ps (postscript) files
   */
  
  if(/^\%PDF\-/.test(header)){
    return "application/pdf"
  }

  /* must check for eps before ps */
  if( /^\%\!PS\-Adobe\-... EPSF\-/s.test(header) ){
    return "application/eps"
  }

  if( /^\%\!PS\-Adobe\-/.test(header) ){
    return "application/postscript"
  }

  /* others: */

  /* xpm formats */
  if( /^\!\sXPM2/.test(header) ){
    return "image/x-xpixmap" /* xpm2 */
  }
  if( /^\/\*\sXPM\s\*\//.test(header)){
    return "image/x-xpixmap" /* xpm3 */
  }

  if( isBinary(header) ){
    /* it's binary */

    if(/^7z\xBC\xAF\x27\x1C/.test(header)){
      return "application/x-7z-compressed"
    }

    /* test for apng, must come before png check */
    if(/^\x89PNG\x0D\x0A\x1A\x0A(.*?)acTL(.*?)IDAT/s.test(header)){
      return "image/apng"
    }

    if(/^\x89PNG\x0D\x0A\x1A\x0A/.test(header)){
      return "image/png"
    }

    if(/^\x67\x6C\x54\x46\x02\x00\x00\x00/.test(header)){
      return "model/gltf-binary"
    }

    if(/^\x4F\x54\x54\x4F\x00/.test(header)){
      return "font/otf"
    }

    if(/^IMPM/.test(header)){
      return "audio/x-it"
    }

    if(/^....(free|moov|wide)/s.test(header)){
      return "video/quicktime"
    }

    if(/^....mdat/s.test(header)){
      return "video/quicktime" // mjpeg
    }

    if(/^\x00\x00\x01\xBA\x21/.test(header)){
      return "video/MP1S" // {offset: 4, mask: [\xF1]} //  MPEG-PS, MPEG-1 Part 1 // May also be .ps, .mpeg
    }

    if(/^\x00\x00\x01\xBA\x44/.test(header)){
      return "video/MP2P"  // {offset: 4, mask: [\xC4]} // MPEG-PS, MPEG-2 Part 1 // May also be .mpg, .m2p, .vob or .sub
    }

    if(/^\x00\x00\x01(\xBA|\xB3)/.test(header)){
      return "video/mpeg"
    }

    if(/^\x00\x01\x00\x00\x00/.test(header)){
      return "font/ttf"
    }

    if(/^\x47.{187}\x47/s.test(header)){
      return "video/mp2t" // Raw MPEG-2 transport stream (188-byte packets)
    }

    if(/^....\x47.{191}\x47/s.test(header)){
      return "video/mp2t" // Blu-ray Disc Audio-Video (BDAV) MPEG-2 transport stream has 4-byte TP_extra_header before each 188-byte packet
    }


    if( /^\x47.{187}\x47/s.test(header) ){
      return "video/mp2t" // Raw MPEG-2 transport stream (188-byte packets)
    }
    
    if( /^....\x47.{191}\x47/s.test(header) ){
      return "video/mp2t" // Blu-ray Disc Audio-Video (BDAV) MPEG-2 transport stream has 4-byte TP_extra_header before each 188-byte packet
    }
    
    if( /^\xAB\x4B\x54\x58\x20\x31\x31\xBB\x0D\x0A\x1A\x0A/.test(header) ){
      return "image/ktx"
    }
    
    // bruh i have no idea what most of these even are and they havent been tested and probably never will be but what the fuck ever
    
    if( /^\xED\xAB\xEE\xDB/.test(header) ){
      return "application/x-rpm"
    }
    
    if( /^\xC5\xD0\xD3\xC6/s.test(header) ){
      return "application/eps"
    }
    
    if( /^\x28\xB5\x2F\xFD/.test(header) ){
      return "application/zstd"
    }
    
    if( /^\x7F\x45\x4C\x46/.test(header) ){
      return "application/x-elf"
    }
    
    if( /^\x21\x42\x44\x4E/.test(header) ){
      return "application/vnd.ms-outlook"
    }

    if( /^PAR1/.test(header) ){
      return "application/x-parquet"
    }
    
    if( /^\x0B\x77/.test(header) ){
      return "audio/vnd.dolby.dd-raw"
    }

    if( /^\x78\x01/.test(header) ){
      return "application/x-apple-diskimage"
    }
    
    if( /^MZ/.test(header) ){
      return "application/x-msdownload"
    }
    
    if( /^(\x1F\xA0|\x1F\x9D)/.test(header) ){
      return "application/x-compress"
    }

    if( /^GIF/.test(header) ){
      return "image/gif"
    }

    if( /^(\x43|\x46)\x57\x53/.test(header) ){
      return "application/x-shockwave-flash"
    }

    if( /^\x49\x49\xBC/.test(header) ){
      return "image/vnd.ms-photo"
    }

    if( /^\x42\x5A\x68/.test(header) ){
      return "application/x-bzip2"
    }

    if( /^MP\+/.test(header) ){
      return "audio/x-musepack"
    }

    if( /^\xFF\xD8\xFF\xF7/.test(header) ){
      return "image/jls" // JPG7/SOF55, indicating a ISO/IEC 14495 / JPEG-LS file
    }

    if( /^FLIF/.test(header) ){
      return "image/flif"
    }

    if( /^8BPS/.test(header) ){
      return "image/vnd.adobe.photoshop"
    }

    if( /^........WEBP/s.test(header) ){
      return "image/webp"
    }

    if( /^MPCK/.test(header) ){
      return "audio/x-musepack" // Musepack, SV8
    }

    if( /^FORM/.test(header) ){
      return "audio/aiff"
    }

    if( /^icns/.test(header) ){
      return "image/icns"
    }

/* ([-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?\.?) */

    /* ZIP and ZIP-LIKE FILES */

    if(  /^PK\x03\x04.{32}\x70\x65\x61\x70\x70\x6C\x69\x63\x61\x74\x69\x6F\x6E\x2F\x65\x70\x75\x62\x2B\x7A\x69\x70/s.test(header) ){
      return "application/epub+zip"
    }
    if(  /^PK\x03\x04(.*?)mimetype(.*?)application\/x\-krita/s.test(header) ){
      return "application/x-krita"
    }
    if(  /^PK\x03\x04(.*?)Document\.archive/s.test(header) ){
      return "application/x-procreate"
    }

    if( /^PK\x03\x04(.*?)mimetypeimage\/openraster/s.test(header)){
      return "image/openraster"
    }

    /* if none of the above, otherwise just a reguilar zip file... */
    if(  /^PK(\x03|\x05|\x07)(\x04|\x06|\x08)/.test(header) ){
      return "application/zip"
    }



    if(  /^CSFCHUNK\x00\x00/.test(header) ){
      return "application/x-clip-studio"
    }
    if(  /^OggS........................OpusHead/s.test(header) ){ return "audio/opus" }
    if(  /^OggS........................\x80theora/s.test(header) ){ return "video/ogg" }
    if(  /^OggS........................\x01video\x00/s.test(header) ){ return "video/ogg" }
    if(  /^OggS........................\x7FFLAC/s.test(header) ){ return "audio/ogg" }
    if(  /^OggS........................Speex\x20\x20/s.test(header) ){ return "audio/ogg" }
    if(  /^OggS........................\x01vorbis/s.test(header) ){ return "audio/ogg" }
    if(  /^OggS/.test(header) ){ return "application/ogg" }


    if(  /^MThd/.test(header) ){
      return "audio/midi"
    }
    if(  /^\x1a\x45\xdf\xa3(.*?)\x42\x82.matroska/s.test(header) ){
      return "video/x-matroska"
    }
    if(  /^\x1a\x45\xdf\xa3(.*?)\x42\x82.webm/s.test(header) ){
      return "video/webm"
    }

    if(  /^\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9/.test(header) ){
      if(
          /.{10}\x40\x9E\x69\xF8\x4D\x5B\xCF\x11\xA8\xFD\x00\x80\x5F\x5C\x44\x2C/s.test(header)
        && /.{10}\xC0\xEF\x19\xBC\x4D\x5B\xCF\x11\xA8\xFD\x00\x80\x5F\x5C\x44\x2B/s.test(header)
      ){
        return "video/x-ms-asf"      
      }else if(/.{10}\x40\x9E\x69\xF8\x4D\x5B\xCF\x11\xA8\xFD\x00\x80\x5F\x5C\x44\x2B/s.test(header)){
        return "audio/x-ms-wma"
      }else if(/.{10}\xC0\xEF\x19\xBC\x4D\x5B\xCF\x11\xA8\xFD\x00\x80\x5F\x5C\x44\x2B/s.test(header)){
        return "video/x-ms-wmv"
      }else{
        return "application/vnd.ms-asf"
      }
    }


      
    if(  /^....ftypavi(f|s)/s.test(header) ){ return "image/avif" }
    if(  /^....ftypmif1/s.test(header) ){ return "image/heif" }
    if(  /^....ftypmsf1/s.test(header) ){ return "image/heif-sequence" }
    if(  /^....ftyphei(c|x)/s.test(header) ){ return "image/heic" }
    if(  /^....ftyphev(c|x)/s.test(header) ){ return "image/heic-sequence" }
    if(  /^....ftypqt/s.test(header) ){ return "video/quicktime" }
    if(  /^....ftypM4V.....M4V\x20M4A\x20/s.test(header) ){ return "mp4","video/mp4" /* m4v+m4a */ }
    if(  /^....ftypM4V((H|P)?)/s.test(header) ){ return "video/x-m4v" }
    if(  /^....ftypM4P/s.test(header) ){ return "audio/mp4a-latm"  /* itunes audio. yes it is m4p, do not mistype as  mp4 */ }
    if(  /^....ftypM4B/s.test(header) ){ return "audio/mp4a-latm"  /* itunes audio book */ }
    if(  /^....ftypM4A/s.test(header) ){ return "audio/x-m4a" }
    if(  /^....ftypF4V/s.test(header) ){ return "video/mp4" }
    if(  /^....ftypF4P/s.test(header) ){ return "video/mp4" }
    if(  /^....ftypF4A/s.test(header) ){ return "audio/mp4" }
    if(  /^....ftypF4B/s.test(header) ){ return "audio/mp4" }
    if(  /^....ftypcrx/s.test(header) ){ return "image/x-canon-cr3" }
    if(  /^....ftyp3g2/s.test(header) ){ return "video/3gpp2" }
    if(  /^....ftyp3g/s.test(header) ){ return "video/3gpp" }
    if(  /^....ftyp(mp41|mp42|isom|iso2|mmp4|dash)/s.test(header) ){ return "video/mp4" }
    if(  /^....ftyp3g/s.test(header) ){ return "video/3gpp" }
    if(  /^....ftypavcl/s.test(header) ){ return "video/3gpp" }
    if(  /^....ftyp/s.test(header) ){
      return "application/mpeg"  // otherwise some application of mpeg
    }
    if(  /^3gp5/s.test(header) ){
      return "video/mp4" // not sure about this one
    }
    
    if(  /^\x00\x00\x00\x0C\x6A\x50\x20\x20\x0d\x0A\x87\x0A/.test(header) ){
      if(/^.{20}\x6A\x70\x32\x20/s.test(header)){
        return "image/jp2"
      }else if(/^.{20}\x6A\x70\x78\x20/s.test(header)){
        return "image/jpx"
      }else if(/^.{20}\x6A\x70\x6D\x20/s.test(header)){
        return "image/jpm"
      }else if(/^.{20}\x6D\x6A\x70\x32/s.test(header)){
        return "image/mj2"
      }
    }
    if(  /^ID3/s.test(header) ){
      return "audio/mpeg" // mp3 with id3 container
    }
    if(  /^\xFF(\xE2|\xE3|\xF2|\xF3|\xFA|\xFB)/.test(header) ){ return "audio/mpeg" } // mp3
    if(  /^\xFF(\xE4|\xE5|\xF4|\xF5|\xFC|\xFD)/.test(header) ){ return "audio/mpeg" } // mp2
    if(  /^\xFF(\xE6|\xE7|\xF6|\xF7|\xFE|\xFF)/.test(header) ){ return "audio/mpeg" } // mp1
    // these were found by me through testing but i still cant discern the patterns here... im not smart enough
    if(  /^\xC2\x0E/.test(header) ){ return "audio/mpeg" } // mp1
    if(  /^\xC2\xC1/.test(header) ){ return "audio/mpeg" } // mp1
    if(  /^\xC2\xD6/.test(header) ){ return "audio/mpeg" } // mp1
    if(  /^\xC4\x7B/.test(header) ){ return "audio/mpeg" } // mp1
    if(  /^\xC8\x93/.test(header) ){ return "audio/mpeg" } // mp1
    if(  /^\xE4\x0F/.test(header) ){ return "audio/mpeg" } // mp1
    // from gary kessler's list
    if(  /^\xFF\xF1/.test(header) ){
      return "audio/aac" // MPEG-4 Advanced Audio Coding (AAC) Low Complexity (LC) audio file
    }
    if(  /^\xFF\xF9/.test(header)){
      return "audio/aac" // MPEG-2 Advanced Audio Coding (AAC) Low Complexity (LC) audio file
    }
  
    if(  /^\xFF(\xFB|\xF3|\xF2)/.test(header) ){
      // MPEG-1 Layer 3 file without an ID3 tag or with an ID3v1 tag (which is appended at the end of the file)
      return "audio/mpeg"
    }
    if(  /^\xFF(\xF0|\xF1|\xF2|\xF3|\xF4|\xF5|\xF6|\xF7|\xF8|\xF9|\xFA|\xFB|\xFC|\xFD|\xFE|\xFF)/.test(header) ){
      return "audio/mpeg"
    }

    if(  /^\xFF(\xE0|\xE1|\xE2|\xE3|\xE4|\xE5|\xE6|\xE7|\xE8|\xE9|\xEA|\xEB|\xEC|\xED|\xEE|\xEF)/.test(header) ){
      return "audio/mpeg"
    }

    if(  /^wOFF(\x00\x01\x00\x00|OTTO)/.test(header) ){
      return "font/woff"
    }

    if(  /^wOF2(\x00\x01\x00\x00|OTTO)/.test(header) ){
      return "font/woff2"
    }

    if(  /^(\xD4\xC3\xB2\xA1|\xA1\xB2\xC3\xD4)/.test(header) ){
      return "application/vnd.tcpdump.pcap"
    }

    if(  /^DSD\s/.test(header) ){
      // Sony DSD Stream File (DSF) (Non-standard mime)
      return "audio/x-dsf"
    }
    if(  /^LZIP/.test(header) ){
      return "application/x-lzip"
    }
    if(  /^fLaC/.test(header) ){
      return "audio/x-flac"
    }
    if(  /^\x42\x50\x47\xFB/.test(header) ){
      return "image/bpg"
    }
    if(  /^wvpk/.test(header) ){
      return "audio/wavpack"
    }
    if(  /^\x00\x61\x73\x6D/.test(header) ){
      return "application/wasm"
    }
    if(  /^MAC\s/.test(header) ){
      return "audio/ape"
    }
    if(  /^SQLi/.test(header) ){
      return "application/x-sqlite3"
    }
    if(  /^Cr24/.test(header) ){
      return "application/x-google-chrome-extension"
    }
    if(  /^(MSCF|ISc\()/.test(header) ){
      return "application/vnd.ms-cab-compressed"
    }
    if(  /^\xFF\xD8\xFF/.test(header) ){
      return "image/jpeg"
    }
    if(  /^BM/.test(header) ){
      return "image/bmp"
    }
    if(  /^\x1F\x8B\x08/.test(header) ){
      return "application/gzip"
    }
    if(  /^\x2E\x52\x4D\x46/.test(header) ){
      return "audio/x-pn-realaudio"
    }
    if(  /^\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C/.test(header) ){
      return "video/x-ms-asf"
    }
    if(  /^I\sI/.test(header) ){
      return "image/tiff"
    }
    if(  /^II\*/.test(header) ){
      return "image/tiff"
    }
    if(  /^MM\x00\*/.test(header) ){
      return "image/tiff"
    }
    if(  /^RIFF....WEBPVP/s.test(header) ){
      return "image/webp"
    }
    if(  /^Rar\!\x1A\x07\x00/.test(header) ){
      return "application/x-rar-compressed"
    }
    if(  /^\xD7\xCD\xC6\x9A/.test(header) ){
      return "application/x-msmetafile"
    }
    if(  /^(CWS|FWS)/.test(header) ){
      return "application/x-shockwave-flash"
    }
    if(  /^FLV/.test(header) ){
      return "video/x-flv"
    }
    if(  /^\#define/.test(header) ){
      return "image/x-xbitmap"
    }
    if(  /^RIFF....WAVEfmt\s/s.test(header) ){
      return "audio/wav"
    }
    if(  /^RIFF....AVI\sLIST/s.test(header) ){
      return "video/avi"
    }  
    if(  /^\#\!AMR\n/.test(header) ){
      return "audio/amr"
    }
    if(  /^II\x2a\x00\x10\x00\x00\x00CR/.test(header) ){
      return "image/x-canon-cr2"
    }
    if(  /^II\x1a\x00\x00\x00HEAPCCDR/.test(header) ){
      return "image/x-canon-crw"
    }
    if(  /^\x00MRM/.test(header) ){
      return "image/x-minolta-mrw"
    }
    if(  /^MMOR/.test(header) ){
      return "image/x-olympus-orf" // big endian
    }
    if(  /^IIRO/.test(header) ){
      return "image/x-olympus-orf" // little endian
    }
    if(  /^IIRS/.test(header) ){
      return "image/x-olympus-orf" // little endian
    }
    if(  /^FUJIFILMCCD-RAW\s/.test(header) ){
      return "image/x-fuji-raf"
    }
    if(  /^IIU\x00\x08\x00\x00\x00/.test(header) ){
      return "image/x-panasonic-raw" // Panasonic .raw
    }
    if(  /^IIU\x00\x18\x00\x00\x00/.test(header) ){
      return "image/x-panasonic-raw" // Panasonic .rw2
    }
    if(  /^MMMMRaw/.test(header) ){
      return "image/x-phaseone-raw"
    }
    if(  /^FOVb/.test(header) ){
      return "image/x-x3f"
    }
    if(  /^BLENDER/.test(header) ){
      return "application/x-blender"
    }
    if(  /^\{\\rtf/.test(header) ){
      return "application/rtf"
    }
    if(  /^\x4E\x45\x53\x1A/.test(header) ){
      return "application/x-nintendo-nes-rom"
    }
    if(  /^\x67\x6c\x54\x46\x02\x00\x00\x00/.test(header) ){
      "model/gltf-binary"
    }
    if(  /^\x00\x00\x02\x00/s.test(header) ){
      "image/x-icon" // cur file
    } 
    if(  /^\x00\x00\x01\x00/s.test(header) ){
      return "image/x-icon" // ico file
    }



    /* if all else fails, return this for binary files as the default */
    return "application/octet-stream"
  }else{
    /* it's a (probably) plaintext file */
    /* BOM */
    if(/^\xFE\xFF/.test(header)){ return "text/plain; charset=utf-16be" }
    if(/^\xFF\xFE/.test(header)){ return "text/plain; charset=utf-16le" }
    if(/^\xEF\xBB\xBF/.test(header)){ return "text/plain; charset=utf-8" }
    /* obj file */
    if(/^(\#(.*?)\n|v\s([-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?\.?)\s([-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?\.?)\s([-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?\.?)\n)/s.test(header)){
      if(!header.startsWith("#define ")){
        return "model/obj"
      }
    }
    var trimmed = header.trim();
    if(/^\</.test(trimmed)){
      /* html, xml, or svg... */
      /* get rid of a comment if it exists before the start of the file */
      trimmed = trimmed.toLowerCase().replaceAll("\n","").replace(/^<!--(.*?)-->/s);
      if(trimmed.startsWith("<svg")){
        return "image/svg+xml"
      }
      if(trimmed.startsWith("<?xml")){
        if(/\<feed/.test(trimmed) || /\<rss/.test(trimmed) ){
          return "application/atom+xml";
        }
        if(/\<svg/.test(trimmed)){
          /**
           * @todo might need to be more precise abt this
           */
          return "image/svg+xml"
        }
        return "text/xml"
      }
      if(trimmed.startsWith("<!doctype ")){
        if(trimmed.startsWith("<!doctype svg")){
          return "image/svg+xml"
        }
        if(trimmed.startsWith("<!doctype html")){
          return "text/html"
        }
      }
    }
    /* test for possible json */
    /**
     * @todo might need to be more precise abt this
     */
    if(
      (trimmed.startsWith("{") && trailer.endsWith("}")) 
      ||
      (trimmed.startsWith("[") && trailer.endsWith("]"))
    ){
      return "application/json"
    }

    /* if all else fails, return this for plaintext files as the default */
    return "text/plain"
  }
  
}

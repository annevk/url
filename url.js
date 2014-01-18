/* Any copyright is dedicated to the Public Domain.
 * http://creativecommons.org/publicdomain/zero/1.0/ */

/*
 * Does not process domain names or IP addresses.
 * Does not handle encoding for the query parameter.
 */
function jURL(url, base, encoding) {
  var relative = {
        "ftp": 21,
        "file" : 0,
        "gopher": 70,
        "http": 80,
        "https": 443,
        "ws": 80,
        "wss": 443
      },
      scheme = "",
      schemeData = "",
      username = "",
      password = null,
      host = "",
      port = "",
      path = [],
      query = "",
      fragment = "",
      input = url.replace(/^[ \t\r\n\f]+|[ \t\r\n\f]+$/g, ""),
      isInvalid = false,
      isRelative = false,
      isRelativeScheme = function(s) {
        s = s || scheme
        return relative.hasOwnProperty(s)
      },
      clear = function() {
        scheme = ""
        schemeData = ""
        username = ""
        password = null
        host = ""
        port = ""
        path = []
        query = ""
        fragment = ""
        isInvalid = false
        isRelative = false
      }
  encoding = encoding || "utf-8"

  Object.defineProperties(this, {
    /* implementation detail */
    "_scheme": { get: function() { return scheme } },
    "_username": { get: function() { return username } },
    "_password": { get: function() { return password } },
    "_host": { get: function() { return host } },
    "_port": { get: function() { return port } },
    "_path": { get: function() { return path } },
    "_query": { get: function() { return query } },
    "_fragment": { get: function() { return fragment } },

    /* URL decomposition attributes */
    "href": {
      get: function() { return isInvalid ? url : this.protocol + (isRelative ? "//" + (("" != username || null != password) ? username + (null != password ? ":" + password : "") + "@" : "") + this.host : "") + this.pathname + query + fragment },
      set: function(_) {
        clear()
        parse(_)
      }
    },
    "protocol": {
      get: function() { return scheme + ":" },
      set: function(_) {
        if(isInvalid) {
          return
        }
        parse(_ + ":", "scheme start")
      }
    },
    "host": {
      get: function() { return isInvalid ? "" : port ? host + ":" + port : host },
      set: function(_) {
        if(isInvalid || !isRelative) {
          return
        }
        parse(_, "host")
      }
    },
    "hostname": {
      get: function() { return host },
      set: function(_) {
        if(isInvalid || !isRelative) {
          return
        }
        parse(_, "hostname")
      }
    },
    "port": {
      get: function() { return port },
      set: function(_) {
        if(isInvalid || !isRelative) {
          return
        }
        parse(_, "port")
      }
    },
    "pathname": {
      get: function() { return isInvalid ? "" : isRelative ? "/" + path.join("/") : schemeData },
      set: function (_) {
        if(isInvalid || !isRelative) {
          return
        }
        path = []
        parse(_, "relative path start")
      }
    },
    "search": {
      get: function() { return isInvalid || !query || "?" == query ? "" : query },
      set: function(_) {
        if(isInvalid || !isRelative) {
          return
        }
        query = "?"
        if("?" == _[0]) {
          _ = _.substr(1)
        }
        parse(_, "query")
      }
    },
    "hash": {
      get: function() { return isInvalid || !fragment || "#" == fragment ? "" : fragment },
      set: function(_) {
        if(isInvalid) {
          return
        }
        fragment = "#"
        if("#" == _[0]) {
          _ = _.substr(1)
        }
        parse(_, "fragment")
      }
    }
  })

  function parse(input, stateOverride) {
    var EOF = undefined,
        ALPHA = /[a-zA-Z]/,
        ALPHANUMERIC = /[a-zA-Z0-9\+\-\.]/,
        state = stateOverride || "scheme start",
        cursor = 0,
        buffer = "",
        seenAt = false,
        seenBracket = false,
        invalid = function () {
          clear()
          isInvalid = true
        },
        errors = [],
        err = function(message) {
          errors.push(message)
        },
        percentEscape = function (c) {
          var unicode = c.charCodeAt(0)
          if(unicode > 0x20 &&
             unicode < 0x7F &&
             // " # < > ? `
             [0x22, 0x23, 0x3C, 0x3E, 0x3F, 0x60].indexOf(unicode) == -1
            ) {
            return c
          }
          return encodeURIComponent(c)
        },
        percentEscapeQuery = function(c) {
          // XXX This actually needs to encode c using encoding and then
          // convert the bytes one-by-one.

          var unicode = c.charCodeAt(0)
          if(unicode > 0x20 &&
             unicode < 0x7F &&
             // " # < > ` (do not escape "?")
             [0x22, 0x23, 0x3C, 0x3E, 0x60].indexOf(unicode) == -1
            ) {
            return c
          }
          return encodeURIComponent(c)
        },
        IDNAToASCII = function (h) {
          if("" == h) {
            invalid()
          }
          // XXX
          return h.toLowerCase()
        },
        relativePathDotMapping = {
          "%2e": ".",
          ".%2e" : "..",
          "%2e." : "..",
          "%2e%2e" : ".."
        }

    while((input[cursor-1] != EOF || cursor == 0) && !isInvalid) {
      var c = input[cursor]
      if("scheme start" == state) {
        if(c && ALPHA.test(c)) {
          buffer += c.toLowerCase() // ASCII-safe
          state = "scheme"
        } else if(!stateOverride) {
          buffer = ""
          state = "no scheme"
          continue
        } else {
          err("Invalid scheme.")
          break
        }
      } else if("scheme" == state) {
        if(c && ALPHANUMERIC.test(c)) {
          buffer += c.toLowerCase() // ASCII-safe
        } else if(":" == c) {
          scheme = buffer
          buffer = ""
          if(stateOverride) {
            break
          }
          if(isRelativeScheme(scheme)) {
            isRelative = true
          }
          if("file" == scheme) {
            state = "relative"
          } else if(isRelative && base && base._scheme == scheme) {
            state = "relative or authority"
          } else if(isRelative) {
            state = "authority first slash"
          } else {
            state = "scheme data"
          }
        } else if(!stateOverride) {
          buffer = ""
          cursor = 0
          state = "no scheme"
          continue
        } else if(EOF == c) {
          break
        } else {
          err("Code point not allowed in scheme: " + c)
          break
        }
      } else if("scheme data" == state) {
        if("?" == c) {
          query = "?"
          state = "query"
        } else if("#" == c) {
          fragment = "#"
          state = "fragment"
        } else {
          // XXX error handling
          if(EOF != c && "\t" != c && "\n" != c && "\r" != c) {
            schemeData += percentEscape(c)
          }
        }
      } else if("no scheme" == state) {
        if(!base || !(isRelativeScheme(base._scheme))) {
          err("Missing scheme.")
          invalid()
        } else {
          state = "relative"
          continue
        }
      } else if("relative or authority" == state) {
        if("/" == c && "/" == input[cursor+1]) {
          state = "authority ignore slashes"
        } else {
          err("Expected /, got: " + c)
          state = "relative"
          continue
        }
      } else if("relative" == state) {
        isRelative = true
        if("file" != scheme)
          scheme = base._scheme
        if(EOF == c) {
          host = base._host
          port = base._port
          path = base._path
          query = base._query
          break
        } else if("/" == c || "\\" == c) {
          if("\\" == c)
            err("\\ is an invalid code point.")
          state = "relative slash"
        } else if("?" == c) {
          host = base._host
          port = base._port
          path = base._path
          query = "?"
          state = "query"
        } else if("#" == c) {
          host = base._host
          port = base._port
          path = base._path
          query = base._query
          fragment = "#"
          state = "fragment"
        } else {
          var nextC = input[cursor+1]
          var nextNextC = input[cursor+2]
          if(
            "file" != scheme || !ALPHA.test(c) ||
            (nextC != ":" && nextC != "|") ||
            (EOF != nextNextC && "/" != nextNextC && "\\" != nextNextC && "?" != nextNextC && "#" != nextNextC)) {
            host = base._host
            port = base._port
            path = base._path
            path.pop()
          }
          state = "relative path"
          continue
        }
      } else if("relative slash" == state) {
        if("/" == c || "\\" == c) {
          if("\\" == c) {
            err("\\ is an invalid code point.")
          }
          if("file" == scheme) {
            state = "file host"
          } else {
            state = "authority ignore slashes"
          }
        } else {
          if("file" != scheme) {
            host = base._host
            port = base._port
          }
          state = "relative path"
          continue
        }
      } else if("authority first slash" == state) {
        if("/" == c) {
          state = "authority second slash"
        } else {
          err("Expected '/', got: " + c)
          state = "authority ignore slashes"
          continue
        }
      } else if("authority second slash" == state) {
        state = "authority ignore slashes"
        if("/" != c) {
          err("Expected '/', got: " + c)
          continue
        }
      } else if("authority ignore slashes" == state) {
        if("/" != c && "\\" != c) {
          state = "authority"
          continue
        } else {
          err("Expected authority, got: " + c)
        }
      } else if("authority" == state) {
        if("@" == c) {
          if(seenAt) {
            err("@ already seen.")
            buffer += "%40"
          }
          seenAt = true
          for(var i = 0; i < buffer.length; i++) {
            var cp = buffer[i]
            if("\t" == cp || "\n" == cp || "\r" == cp) {
              err("Invalid whitespace in authority.")
              continue
            }
            // XXX check URL code points
            if(":" == cp && null === password) {
              password = ""
              continue
            }
            var tempC = percentEscape(cp)
            ;(null !== password) ? password += tempC : username += tempC
          }
          buffer = ""
        } else if(EOF == c || "/" == c || "\\" == c || "?" == c || "#" == c) {
          cursor -= buffer.length
          buffer = ""
          state = "host"
          continue
        } else {
          buffer += c
        }
      } else if("file host" == state) {
        if(EOF == c || "/" == c || "\\" == c || "?" == c || "#" == c) {
          if(buffer.length == 2 && ALPHA.test(buffer[0]) && (buffer[1] == ":" || buffer[1] == "|")) {
            state = "relative path"
          } else if(buffer.length == 0) {
            state = "relative path start"
          } else {
            host = IDNAToASCII(buffer)
            buffer = ""
            state = "relative path start"
          }
          continue
        } else if("\t" == c || "\n" == c || "\r" == c) {
          err("Invalid whitespace in file host.")
        } else {
          buffer += c
        }
      } else if("host" == state || "hostname" == state) {
        if(":" == c && !seenBracket) {
          // XXX host parsing
          host = IDNAToASCII(buffer)
          buffer = ""
          state = "port"
          if("hostname" == stateOverride) {
            break
          }
        } else if(EOF == c || "/" == c || "\\" == c || "?" == c || "#" == c) {
          host = IDNAToASCII(buffer)
          buffer = ""
          state = "relative path start"
          if(stateOverride) {
            break
          }
          continue
        } else if("\t" != c && "\n" != c && "\r" != c) {
          if("[" == c) {
            seenBracket = true
          } else if("]" == c) {
            seenBracket = false
          }
          buffer += c
        } else {
          err("Invalid code point in host/hostname: " + c)
        }
      } else if("port" == state) {
        if(/[0-9]/.test(c)) {
          buffer += c
        } else if(EOF == c || "/" == c || "\\" == c || "?" == c || "#" == c || stateOverride) {
          if("" != buffer) {
            var temp = parseInt(buffer, 10)
            if(temp != relative[scheme]) {
              port = temp + ""
            }
            buffer = ""
          }
          if(stateOverride) {
            break
          }
          state = "relative path start"
          continue
        } else if("\t" == c || "\n" == c || "\r" == c) {
          err("Invalid code point in port: " + c)
        } else {
          invalid()
        }
      } else if("relative path start" == state) {
        if("\\" == c)
          err("'\\' not allowed in path.")
        state = "relative path"
        if("/" != c && "\\" != c) {
          continue
        }
      } else if("relative path" == state) {
        if(EOF == c || "/" == c || "\\" == c || (!stateOverride && ("?" == c || "#" == c))) {
          if("\\" == c) {
            err("\\ not allowed in relative path.")
          }
          if(relativePathDotMapping.hasOwnProperty(buffer.toLowerCase())) {
            buffer = relativePathDotMapping[buffer.toLowerCase()]
          }
          if(".." == buffer) {
            path.pop()
            if("/" != c && "\\" != c) {
              path.push("")
            }
          } else if("." == buffer && "/" != c && "\\" != c) {
            path.push("")
          } else if("." != buffer) {
            if("file" == scheme && path.length == 0 && buffer.length == 2 && ALPHA.test(buffer[0]) && buffer[1] == "|") {
              buffer = buffer[0] + ":"
            }
            path.push(buffer)
          }
          buffer = ""
          if("?" == c) {
            query = "?"
            state = "query"
          } else if("#" == c) {
            fragment = "#"
            state = "fragment"
          }
        } else if("\t" != c && "\n" != c && "\r" != c) {
          buffer += percentEscape(c)
        }
      } else if("query" == state) {
        if(!stateOverride && "#" == c) {
          fragment = "#"
          state = "fragment"
        } else if(EOF != c && "\t" != c && "\n" != c && "\r" != c) {
          query += percentEscapeQuery(c)
        }
      } else if("fragment" == state) {
        if(EOF != c && "\t" != c && "\n" != c && "\r" != c) {
          fragment += c
        }
      }
      cursor++
    }
  }
  parse(input)
}

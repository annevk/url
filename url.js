/*
 * Does not process domain names or IP addresses.
 * Does not handle encoding for the query parameter.
 */
function URL(url, base) {
  var hierarchical = {
        "ftp": 21,
        "gopher": 70,
        "http": 80,
        "https": 443,
        "ws": 80,
        "wss": 443
      },
      scheme = "",
      userinfo = "",
      host = "",
      port = "",
      path = [],
      query = null,
      fragment = null,
      isInvalid = false,
      isHierarchical = function(s) {
        s = s || scheme
        return hierarchical.hasOwnProperty(s)
      },
      clear = function() {
        scheme = ""
        userinfo = ""
        host = ""
        port = ""
        path = []
        query = null
        fragment = null
      }

  Object.defineProperties(this, {
    /* implementation detail */
    "_scheme": { get: function() { return scheme } },
    "_userinfo": { get: function() { return userinfo } },
    "_host": { get: function() { return host } },
    "_port": { get: function() { return port } },
    "_path": { get: function() { return path } },
    "_query": { get: function() { return query } },
    "_fragment": { get: function() { return fragment } },

    /* URL decomposition attributes */
    "href": {
      get: function() { return isInvalid ? url : this.protocol + (isHierarchical() ? "//" + (userinfo ? userinfo + "@" : "") + this.host : "") + this.pathname + this.search + this.hash },
      set: function(_) {
        clear()
        parse(_)
      }
    },
    "protocol": {
      get: function() { return isInvalid ? "" : scheme + ":" },
      set: function(_) {
        parse(_ + ":", "scheme start")
      }
    },
    "host": {
      get: function() { return isInvalid ? "" : port ? host + ":" + port : host },
      set: function(_) {
        parse(_, "host")
      }
    },
    "hostname": {
      get: function() { return host },
      set: function(_) {
        parse(_, "hostname")
      }
    },
    "port": {
      get: function() { return port },
      set: function(_) {
        parse(_, "port")
      }
    },
    "pathname": {
      get: function() { return isInvalid ? "" : isHierarchical() ? "/" + path.join("/") : path[0] },
      set: function (_) {
        if(isInvalid || !isHierarchical()) {
          return
        }
        path = []
        parse(_, "hierarchical path start")
      }
    },
    "search": {
      get: function() { return isInvalid || query == null ? "" : "?" + query },
      set: function(_) {
        if(isInvalid || !isHierarchical()) {
          return
        }
        query = ""
        if("?" == _[0]) {
          _ = _.substr(1)
        }
        parse(_, "query")
      }
    },
    "hash": {
      get: function() { return isInvalid || fragment == null ? "" : "#" + fragment },
      set: function(_) {
        if(isInvalid) {
          return
        }
        fragment = ""
        if("#" == _[0]) {
          _ = _.substr(1)
        }
        parse(_, "fragment")
      }
    }
  })

  function parse(url, stateOverride) {
    var EOF = undefined,
        state = stateOverride || "scheme start",
        input = url, // XXX need to trim (but only specific characters)
        cursor = 0,
        buffer = "",
        seenAt = false,
        invalid = function () {
          clear()
          isInvalid = true
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
        }
        IDNAToASCII = function (h) {
          // XXX
          return h.toLowerCase()
        }

    while((input[cursor-1] != EOF || cursor == 0) && !isInvalid) {
      var c = input[cursor]
      if("scheme start" == state) {
        if(c && /[a-zA-Z]/.test(c)) {
          buffer += c.toLowerCase()
          state = "scheme"
        } else if(!stateOverride) {
          buffer = ""
          state = "no scheme"
          continue
        } else {
          break
        }
      } else if("scheme" == state) {
        if(c && /[a-zA-Z0-9\+\-\.]/.test(c)) {
          buffer += c.toLowerCase() // ASCII-safe
        } else if(":" == c) {
          scheme = buffer
          buffer = ""
          if(stateOverride) {
            break
          } else if(isHierarchical()) {
            if(base && base._scheme == scheme) {
              state = "hierarchical"
            } else {
              state = "authority start"
            }
          } else {
            state = "path"
          }
        } else {
          buffer = ""
          cursor = 0
          state = "no scheme"
          continue
        }
      } else if("no scheme" == state) {
        if(!base || !(isHierarchical(base._scheme))) {
          invalid()
        } else {
          state = "hierarchical"
          continue
        }
      } else if("hierarchical" == state) {
        if(c == EOF) {
          scheme = base._scheme
          host = base._host
          port = base._port
          path = base._path
          query = base._query
          break
        } else if("/" == c || "\\" == c) {
          var nextC = input[cursor+1]
          if("/" == nextC || "\\" == nextC) {
            scheme = base._scheme
            state = "authority start"
          } else {
            scheme = base._scheme
            host = base._host
            port = base._port
            state = "hierarchical path start"
            continue
          }
        } else if("?" == c) {
          scheme = base._scheme
          host = base._host
          port = base._port
          path = base._path
          query = ""
          state = "query"
        } else if("#" == c) {
          scheme = base._scheme
          host = base._host
          port = base._port
          path = base._path
          query = base._query
          fragment = ""
          state = "fragment"
        } else {
          scheme = base._scheme
          host = base._host
          port = base._port
          path = base._path
          path.pop()
          state = "hierarchical path start"
          continue
        }
      } else if("authority start" == state) {
        if("/" != c && "\\" != c) {
          state = "authority"
          continue
        }
      } else if("authority" == state) {
        if("@" == c) {
          if(seenAt) {
            userinfo += "%40"
          }
          seenAt = true
          for(var i = 0; i < buffer.length; i++) {
            userinfo += percentEscape(buffer[i])
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
      } else if("host" == state || "hostname" == state) {
        if(":" == c) {
          host = IDNAToASCII(buffer)
          buffer = ""
          if("hostname" == stateOverride) {
            break
          }
          state = "port"
        } else if(EOF == c || "/" == c || "\\" == c || "?" == c || "#" == c) {
          host = IDNAToASCII(buffer)
          buffer = ""
          if(stateOverride) {
            break
          }
          state = "hierarchical path start"
          continue
        } else {
          buffer += c
        }
      } else if("port" == state) {
        if(/[0-9]/.test(c)) {
          buffer += c
        } else if(EOF == c || "/" == c || "\\" == c || "?" == c || "#" == c) {
          if("" != buffer) {
            var temp = parseInt(buffer, 10)
            if(temp != hierarchical[scheme]) {
              port = temp + ""
            }
            buffer = ""
          }
          state = "hierarchical path start"
          continue
        } else if(stateOverride) {
          if("" != buffer) {
            var temp = parseInt(buffer, 10)
            if(temp != hierarchical[scheme]) {
              port = temp + ""
            }
            buffer = ""
          }
          break
        } else {
          invalid()
        }
      } else if("path" == state) {
        path.push("")
        if(!stateOverride && "#" == c) {
          state = "fragment"
        } else if(EOF != c) {
          path[0] += percentEscape(c)
        }
      } else if("hierarchical path start" == state) {
        state = "hierarchical path"
        if("/" != c && "\\" != c) {
          continue
        }
      } else if("hierarchical path" == state) {
        if(EOF == c || "/" == c || "\\" == c || (!stateOverride && ("?" == c || "#" == c))) {
          if(".." == buffer) {
            path.pop()
          } else if("." == buffer && (EOF == c || "?" == c || "#" == c)) {
            path.push("")
          } else if("." != buffer) {
            path.push(buffer)
          }
          buffer = ""
          if("?" == c) {
            query = ""
            state = "query"
          } else if("#" == c) {
            fragment = ""
            state = "fragment"
          }
        } else if("\t" != c && "\n" != c && "\r" != c) {
          buffer += percentEscape(c)
        }
      } else if("query" == state) {
        if(!stateOverride && "#" == c) {
          fragment = ""
          state = "fragment"
        } else if(EOF != c && "\t" != c && "\n" != c && "\r" != c) {
          query += percentEscape(c)
        }
      } else if("fragment" == state) {
        if(EOF != c && "\t" != c && "\n" != c && "\r" != c) {
          fragment += c
        }
      }
      cursor++
    }
  }
  parse(url)
}

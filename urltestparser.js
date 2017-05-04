function URLTestParser(input) {
  var results = []
  var relativeSchemes = ["ftp", "file", "gopher", "http", "https", "ws", "wss"],
      tokenMap = { "\\": "\\", n: "\n", r: "\r", s: " ", t: "\t", f: "\f" }
      resultMap = { s: "scheme", u: "username", pass: "password", h: "host", port: "port", p: "path", q: "query", f: "fragment" },
      results = []
  function Test() {
    this.input = ""
    this.base = ""
    this.output = {
      scheme: "",
      username: "",
      password: null,
      host: "",
      port: "",
      path: "",
      query: "",
      fragment: ""
    }
  }
  input.forEach(function(urltest) {
    if (typeof(urltest) === "string") return // comment
    if(urltest.base === "" || urltest.base === undefined) {
      urltest.base = results[results.length - 1].base
    }
    Object.defineProperties(urltest.output, {
      "href": { get: function() { return !this.scheme ? this.input : this.protocol + (relativeSchemes.indexOf(this.scheme) != -1 ? "//" + (("" != this.username || null != this.password) ? this.username + (null != this.password ? ":" + this.password : "") + "@" : "") + this.host : "") + (this.port ? ":" + this.port : "") + this.path + this.query + this.fragment } },
      "protocol": { get: function() { return this.scheme + ":" } },
      "search": { get: function() { return "?" == this.query ? "" : this.query } },
      "hash": { get: function() { return "#" == this.fragment ? "" : this.fragment } }
    })
    results.push(urltest);
  });
  return results
}

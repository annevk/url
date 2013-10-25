function loadTests(cb) {
    return function() {
        var testFilenames = [1, 2, 3, 4, 5]
        var tests = []
        var loadTest = function(testFilenameIndex) {
          var request = new XMLHttpRequest()
          request.open("GET", 'test/' + testFilenames[testFilenameIndex] + ".json")
          request.send()
          request.responseType = "text"
          if (testFilenameIndex === testFilenames.length - 1) {
            request.onload = function() {
              tests = tests.concat(JSON.parse(request.response))
              cb(tests)
            }
          } else {
            request.onload = function() {
              tests = tests.concat(JSON.parse(request.response))
              loadTest(testFilenameIndex + 1)
            }
          }
        }
        loadTest(0)
    }
}
var path = require('path')

module.exports = {
    entry: path.join(__dirname, '/index.js'),
    externals: {
      'bsv': 'bsv'
    },
    output: {
        library: 'BitDiary',
        path: path.join(__dirname, '/'),
        filename: 'bitdiary.min.js'
    }
  }
  
const path = require('path');

module.exports = {
  entry: './index.js',
  target: 'node',
  mode: 'production',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'index.js',
    library: {
      type: 'commonjs2'
    }
  },
  resolve: {
    extensions: ['.js', '.json']
  },
  // externals: {
  //   // Keep these as external dependencies
  //   '@actions/core': 'commonjs @actions/core',
  //   '@actions/exec': 'commonjs @actions/exec',
  //   '@actions/github': 'commonjs @actions/github',
  //   '@actions/tool-cache': 'commonjs @actions/tool-cache'
  // },
  optimization: {
    minimize: false
  },
  node: {
    __dirname: false,
    __filename: false
  }
};

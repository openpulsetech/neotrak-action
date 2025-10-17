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
  externals: {
    // Bundle all dependencies for GitHub Actions deployment
    // No external dependencies needed
  },
  optimization: {
    minimize: false
  },
  node: {
    __dirname: false,
    __filename: false
  }
};

module.exports = {
  rootDir: './',
  moduleFileExtensions: ['ts', 'js'],
  testMatch: ['**/test/*.test.ts'],
  coveragePathIgnorePatterns: [
    '/node_modules/',
    './cypress',
    './jest.config.js'
  ],
  reporters: [
    'default',
    ['jest-junit', { outputDirectory: 'test-results/jest' }]
  ],
  coverageReporters: ['lcov', 'text', 'text-summary'],
  preset: 'ts-jest',
  setupFiles: ['jest-localstorage-mock']
};

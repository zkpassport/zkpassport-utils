export default {
  testEnvironment: "node",
  transform: {
    "\\.[jt]sx?$": "babel-jest",
  },
  testMatch: ["<rootDir>/src/**/*.test.ts"],
  transformIgnorePatterns: ["/node_modules/(?!(@zkpassport|@zk-kit)/.*)"],
}

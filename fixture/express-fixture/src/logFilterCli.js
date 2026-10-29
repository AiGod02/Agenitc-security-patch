const fs = require("fs");
const path = require("path");

const logPath = path.resolve(__dirname, "../storage/logs/app.log");
const keyword = process.argv[2] || "";
const lines = fs.readFileSync(logPath, "utf8").split(/\r?\n/).filter(Boolean);
const matched = lines.filter((line) => line.includes(keyword));
process.stdout.write(matched.join("\n"));

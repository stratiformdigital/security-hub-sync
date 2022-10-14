import { spawn } from "child_process";
export default class LabeledProcessRunner {
  constructor() {
    this.prefixColors = {};
    this.colors = [
      "1",
      "2",
      "3",
      "4",
      "5",
      "6",
      "9",
      "10",
      "11",
      "12",
      "13",
      "14",
    ];
  }
  formattedPrefix(prefix) {
    let color;
    if (prefix in this.prefixColors) {
      color = this.prefixColors[prefix];
    } else {
      const frontColor = this.colors.shift();
      if (frontColor != undefined) {
        color = frontColor;
        this.colors.push(color);
        this.prefixColors[prefix] = color;
      } else {
        throw "dev.ts programming error";
      }
    }
    let maxLength = 0;
    for (let pre in this.prefixColors) {
      if (pre.length > maxLength) {
        maxLength = pre.length;
      }
    }
    return `\x1b[38;5;${color}m ${prefix.padStart(maxLength)}|\x1b[0m`;
  }
  async run_command_and_output(prefix, cmd, cwd) {
    const proc_opts = {};
    if (cwd) {
      proc_opts["cwd"] = cwd;
    }
    const command = cmd[0];
    const args = cmd.slice(1);
    const proc = spawn(command, args, proc_opts);
    const startingPrefix = this.formattedPrefix(prefix);
    process.stdout.write(`${startingPrefix} Running: ${cmd.join(" ")}\n`);
    proc.stdout.on("data", (data) => {
      const paddedPrefix = this.formattedPrefix(prefix);
      for (let line of data.toString().split("\n")) {
        process.stdout.write(`${paddedPrefix} ${line}\n`);
      }
    });
    proc.stderr.on("data", (data) => {
      const paddedPrefix = this.formattedPrefix(prefix);
      for (let line of data.toString().split("\n")) {
        process.stdout.write(`${paddedPrefix} ${line}\n`);
      }
    });
    return new Promise((resolve, reject) => {
      proc.on("error", (error) => {
        const paddedPrefix = this.formattedPrefix(prefix);
        process.stdout.write(`${paddedPrefix} A PROCESS ERROR: ${error}\n`);
        reject(error);
      });
      proc.on("close", (code) => {
        const paddedPrefix = this.formattedPrefix(prefix);
        process.stdout.write(`${paddedPrefix} Exit: ${code}\n`);
        if (code != 0) {
          throw `Exit ${code}`;
        }
        resolve();
      });
    });
  }
}

const { exec } = require('child_process');

// 需要设置的 Git 信息
const commitMessage = "自动提交更改";
const branch = "main";  // 你希望推送到的分支，通常是 main 或 master
const gitPath = '"C:/Program Files/Git/bin/git.exe"';  // 用双引号包裹路径

async function gitUpload() {
    try {
        console.log("Fetching latest changes...");
        await runGitCommand(`${gitPath} fetch`);

        console.log("Adding files to staging area...");
        await runGitCommand(`${gitPath} add .`);

        console.log(`Committing changes with message: "${commitMessage}"`);
        await runGitCommand(`${gitPath} commit -m "${commitMessage}"`);

        console.log("Pushing changes to remote...");
        await runGitCommand(`${gitPath} push origin ${branch}`);

        console.log("代码已成功提交并推送到 GitHub！");
    } catch (error) {
        console.error("发生了错误：", error);
    }
}

// 执行 Git 命令
function runGitCommand(command) {
    return new Promise((resolve, reject) => {
        exec(command, { cwd: 'D:/code/wasm' }, (error, stdout, stderr) => {
            if (error) {
                reject(`exec error: ${error}`);
                return;
            }
            if (stderr) {
                reject(`stderr: ${stderr}`);
                return;
            }
            resolve(stdout);
        });
    });
}

gitUpload();

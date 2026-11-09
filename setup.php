<?php
require __DIR__.'/server.php';
try {
    $db=database();
    $db->exec("CREATE TABLE IF NOT EXISTS users(id INT PRIMARY KEY AUTO_INCREMENT,email VARCHAR(254) UNIQUE NOT NULL,password_hash VARCHAR(255) NOT NULL,role VARCHAR(12) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    if((int)$db->query('SELECT COUNT(*) FROM users')->fetchColumn()>0){http_response_code(403);exit('Setup is already complete. Delete setup.php.');}
    $error='';
    if($_SERVER['REQUEST_METHOD']==='POST'){
        $c=require __DIR__.'/config.php';
        if(str_starts_with($c['setup_token'],'REPLACE_')||strlen($c['setup_token'])<32||!hash_equals($c['setup_token'],$_POST['token']??''))throw new RuntimeException('Invalid setup secret.');
        $owner=strtolower(trim($_POST['owner']??''));$viewer=strtolower(trim($_POST['viewer']??''));$op=$_POST['owner_password']??'';$vp=$_POST['viewer_password']??'';
        if(!filter_var($owner,FILTER_VALIDATE_EMAIL)||!filter_var($viewer,FILTER_VALIDATE_EMAIL)||$owner===$viewer||strlen($op)<12||strlen($vp)<12||strlen($op)>72||strlen($vp)>72)throw new RuntimeException('Use two different valid emails and passwords of 12–72 bytes.');
        $db->exec("CREATE TABLE IF NOT EXISTS journal(id INT PRIMARY KEY,payload MEDIUMTEXT NULL,version INT NOT NULL DEFAULT 0,updated_at DATETIME NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $db->exec("CREATE TABLE IF NOT EXISTS login_attempts(id INT PRIMARY KEY AUTO_INCREMENT,ip_hash CHAR(64) NOT NULL,created_at DATETIME NOT NULL,INDEX attempt_window(ip_hash,created_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $db->beginTransaction();
        $q=$db->prepare('INSERT INTO users(email,password_hash,role) VALUES (?,?,?)');$q->execute([$owner,password_hash($op,PASSWORD_DEFAULT),'owner']);$q->execute([$viewer,password_hash($vp,PASSWORD_DEFAULT),'viewer']);
        $db->exec('INSERT INTO journal(id,version) VALUES (1,0)');$db->commit();exit('Setup complete. DELETE setup.php now. Open index.html and sign in.');
    }
}catch(Throwable $e){if(isset($db)&&$db->inTransaction())$db->rollBack();$error='Setup failed. Check configuration, secret, distinct emails and password lengths.';}
?><!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Learning journal setup</title><style>body{font:16px system-ui;max-width:540px;margin:50px auto;padding:20px;color:#34254d;background:#f7f5fc}input{display:block;width:100%;box-sizing:border-box;padding:12px;margin:8px 0 20px}button{background:#7551b4;color:white;border:0;padding:14px 25px;border-radius:8px}</style><h1>Private journal · Setup</h1><p>Run once over HTTPS. Accounts can only be created here.</p><p><?=htmlspecialchars($error,ENT_QUOTES,'UTF-8')?></p><form method="post"><label>Setup secret<input name="token" type="password" required autocomplete="off"></label><label>Your email<input name="owner" type="email" required></label><label>Your password (12–72 bytes)<input name="owner_password" type="password" minlength="12" required autocomplete="new-password"></label><label>Sam's email<input name="viewer" type="email" required></label><label>Sam's initial password (12–72 bytes)<input name="viewer_password" type="password" minlength="12" required autocomplete="new-password"></label><button>Create private journal</button></form></html>

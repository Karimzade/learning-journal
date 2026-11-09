<?php
require __DIR__.'/server.php';
try {
    $db=database();$action=$_GET['action']??'me';$method=$_SERVER['REQUEST_METHOD'];
    if($action==='login'&&$method==='POST'){
        // A server-issued token also protects the login request from CSRF.
        csrf();$d=body();$email=strtolower(trim((string)($d['email']??'')));$pass=(string)($d['password']??'');
        if(strlen($email)>254||strlen($pass)>1024)reply(['error'=>'login_failed'],401);
        $ip=hash('sha256',$_SERVER['REMOTE_ADDR']??'unknown');
        $q=$db->prepare('SELECT COUNT(*) FROM login_attempts WHERE ip_hash=? AND created_at>DATE_SUB(UTC_TIMESTAMP(), INTERVAL 15 MINUTE)');$q->execute([$ip]);
        if((int)$q->fetchColumn()>=10)reply(['error'=>'rate_limit'],429);
        $db->prepare('INSERT INTO login_attempts(ip_hash,created_at) VALUES (?,UTC_TIMESTAMP())')->execute([$ip]);
        $q=$db->prepare('SELECT id,email,password_hash,role FROM users WHERE email=?');$q->execute([$email]);$user=$q->fetch(PDO::FETCH_ASSOC);
        $hash=$user?$user['password_hash']:'$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2uheWG/igi.';
        $ok=password_verify($pass,$hash);if(!$user||!$ok)reply(['error'=>'login_failed'],401);
        session_regenerate_id(true);$_SESSION['uid']=(int)$user['id'];$_SESSION['csrf']=bin2hex(random_bytes(32));
        $db->exec('DELETE FROM login_attempts WHERE created_at<DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 DAY)');
        reply(['user'=>['email'=>$user['email'],'role'=>$user['role']],'csrf'=>$_SESSION['csrf']]);
    }
    $_SESSION['csrf']??=bin2hex(random_bytes(32));
    $user=null;if(isset($_SESSION['uid'])){$q=$db->prepare('SELECT email,role FROM users WHERE id=?');$q->execute([$_SESSION['uid']]);$user=$q->fetch(PDO::FETCH_ASSOC)?:null;}
    if($action==='me'&&$method==='GET')reply(['user'=>$user,'csrf'=>$_SESSION['csrf']]);
    if(!$user)reply(['error'=>'unauthorized'],401);
    if($action==='logout'&&$method==='POST'){csrf();$_SESSION=[];session_destroy();reply(['ok'=>true]);}
    if($action==='load'&&$method==='GET'){
        $row=$db->query('SELECT payload,version,updated_at FROM journal WHERE id=1')->fetch(PDO::FETCH_ASSOC);
        reply(['weeks'=>$row&&$row['payload']!==null?json_decode($row['payload'],true):null,'version'=>(int)($row['version']??0),'updated_at'=>$row['updated_at']??null]);
    }
    if($action==='save'&&$method==='POST'){
        csrf();if($user['role']!=='owner')reply(['error'=>'forbidden'],403);$d=body();
        if(!validateWeeks($d['weeks']??null)||!isset($d['version'])||!is_int($d['version']))reply(['error'=>'invalid_data'],422);
        $json=json_encode($d['weeks'],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
        $q=$db->prepare('UPDATE journal SET payload=?, version=version+1, updated_at=UTC_TIMESTAMP() WHERE id=1 AND version=?');$q->execute([$json,$d['version']]);
        if($q->rowCount()!==1)reply(['error'=>'conflict'],409);reply(['version'=>$d['version']+1]);
    }
    reply(['error'=>'not_found'],404);
} catch(Throwable $e){error_log('Learning journal: '.$e->getMessage());reply(['error'=>'server_error'],503);}

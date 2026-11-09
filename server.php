<?php
declare(strict_types=1);
ini_set('display_errors', '0');
header('Cache-Control: no-store, private');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header("Content-Security-Policy: frame-ancestors 'none'");
session_name('learningjournal');
session_set_cookie_params(['lifetime'=>0,'path'=>'/','secure'=>!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off','httponly'=>true,'samesite'=>'Strict']);
session_start();
function reply(array $value, int $status=200): never {
    http_response_code($status);header('Content-Type: application/json; charset=utf-8');
    echo json_encode($value, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);exit;
}
function database(): PDO {
    if(!is_file(__DIR__.'/config.php')) reply(['error'=>'not_configured'],503);
    $c=require __DIR__.'/config.php';
    return new PDO('mysql:host='.$c['db_host'].';dbname='.$c['db_name'].';charset=utf8mb4',$c['db_user'],$c['db_pass'],[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
}
function body(): array {
    $raw=file_get_contents('php://input',false,null,0,2000001);
    if(strlen($raw)>2000000) reply(['error'=>'too_large'],413);
    $d=json_decode($raw,true);if(!is_array($d))reply(['error'=>'invalid_data'],422);return $d;
}
function csrf(): void {
    if(!isset($_SESSION['csrf'])||!hash_equals($_SESSION['csrf'],$_SERVER['HTTP_X_CSRF_TOKEN']??''))reply(['error'=>'session_expired'],403);
}
function validateWeeks(mixed $weeks): bool {
    if(!is_array($weeks)||!array_is_list($weeks)||count($weeks)<1||count($weeks)>104)return false;
    foreach($weeks as $w){
        if(!is_array($w))return false;
        $date=$w['start']??'';if(!is_string($date))return false;
        $d=DateTimeImmutable::createFromFormat('!Y-m-d',$date);
        if(!$d||$d->format('Y-m-d')!==$date||$d->format('N')!=='1')return false;
        if(!in_array($w['status']??null,[0,1,2],true))return false;
        $hours=$w['hours']??null;if($hours!==''&&(!is_numeric($hours)||(float)$hours<0||(float)$hours>168))return false;
        foreach(['live','repo'] as $k){$u=$w[$k]??null;if(!is_string($u)||strlen($u)>2000)return false;if($u!==''&&(!filter_var($u,FILTER_VALIDATE_URL)||!in_array(strtolower(parse_url($u,PHP_URL_SCHEME)??''),['http','https'],true)))return false;}
        foreach(['de','en','fa'] as $lang){if(!isset($w['text'][$lang])||!is_array($w['text'][$lang]))return false;foreach(['title','tasks','learned','problems','prompts','next','other'] as $key){$s=$w['text'][$lang][$key]??'';if(!is_string($s)||strlen($s)>40000)return false;}}
    }return true;
}

rule flask
{
    meta:
        tag="flask"
        description = "flask mem webshell check"
        author = "huashiyi"
    
    strings:
        $str0 = "_request_ctx_stack"
        $str1 = "url_for.__globals__"
        $str2 = "add_url_rule"
        $str3 = "__import__('os').popen"
        $str4 = "exec"
        $str5 = "eval"
        $str6 = "Jinja"
        $str7 = "get_flashed_messages.__getattribute__"
    
    condition:
        ($str0 and $str1 and $str2 and $str3 and $str4 and $str6) or 
        ($str0 and $str1 and $str2 and $str3 and $str5 and $str6) or
        ($str0 and $str7 and $str2 and $str3 and $str4 and $str6) or
        ($str0 and $str7 and $str2 and $str3 and $str5 and $str6)
}

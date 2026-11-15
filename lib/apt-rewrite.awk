# <SEC_SCRIPT_MARKER_v2.3>
# Preserve source format, components, signing keys, options and third-party repos.
function error(msg) { print "拒绝自动换源: " msg > "/dev/stderr"; bad=1; exit 1 }
function official(u,    h,p) {
    if (u !~ /^https?:\/\//) return 0
    h=u; sub(/^https?:\/\//,"",h); sub(/\/.*/,"",h)
    p=u; sub(/^https?:\/\/[^/]+/,"",p); sub(/\/+$/,"",p)
    if (distro=="debian" && p!="/debian" && p!="/debian-security") return 0
    if (distro=="ubuntu" && p!="/ubuntu" && p!="/ubuntu-ports") return 0
    if (h=="mirrors.tuna.tsinghua.edu.cn" || h=="mirrors.aliyun.com" ||
        h=="mirrors.cloud.tencent.com" || h=="mirrors.tencent.com" ||
        h=="mirrors.tencentyun.com" || h=="mirrors.cloud.aliyuncs.com" ||
        h=="mirrors.aliyuncs.com" || h=="mirrors.ustc.edu.cn") return 1
    if (distro=="debian") return h=="deb.debian.org" || h=="security.debian.org" || h=="ftp.debian.org" || h ~ /^ftp\.[a-z][a-z]\.debian\.org$/
    return h=="archive.ubuntu.com" || h=="security.ubuntu.com" || h=="ports.ubuntu.com" || h ~ /^[a-z][a-z]\.archive\.ubuntu\.com$/
}
function valid_suite(s) {
    return s==codename || s==codename "-updates" || s==codename "-backports" || s==codename "-security"
}
function legacy(line,    a,n,i,u,s,pos) {
    if (line !~ /^[ \t]*deb(-src)?[ \t]+/) { print line; return }
    n=split(line,a,/[ \t]+/)
    for (i=1;i<=n;i++) if (a[i] ~ /^https?:\/\//) break
    u=a[i]; s=a[i+1]
    if (!official(u)) { print line; return }
    if (!valid_suite(s)) error("未知或混合发行版套件 " s)
    if (line ~ /trusted[ \t]*=[ \t]*yes|allow-insecure[ \t]*=[ \t]*yes/) error("源配置禁用了签名检查")
    matched++
    pos=index(line,u)
    print substr(line,1,pos-1) (s ~ /-security$/ ? security : mirror) substr(line,pos+length(u))
}
function emit(uris,suites,    i,key,skip) {
    skip=0
    for(i=1;i<=count;i++) {
        if (lines[i] ~ /^[A-Za-z][A-Za-z-]*:/) {
            key=tolower(lines[i]); sub(/:.*/,"",key)
            skip=(key=="uris" || key=="suites")
            if(key=="uris") print "URIs: " uris
            else if(key=="suites") print "Suites: " suites
            else print lines[i]
        } else if (lines[i] ~ /^[ \t]/ && skip) {
            continue
        } else print lines[i]
    }
}
function stanza(    f,key,i,n,urls,ns,suites,known,other,normal,sec,duplicates) {
    if (!count) return
    for (i=1;i<=count;i++) {
        if(lines[i] ~ /^[A-Za-z][A-Za-z-]*:/) {
            key=tolower(lines[i]); sub(/:.*/,"",key)
            if(key in f) duplicates=1
            f[key]=lines[i]; sub(/^[^:]+:[ \t]*/,"",f[key]); sub(/[ \t]+$/,"",f[key])
        } else if(lines[i] ~ /^[ \t]/ && lines[i] !~ /^[ \t]*#/ && key!="") {
            f[key]=f[key] " " lines[i]; gsub(/[ \t]+/," ",f[key])
        }
    }
    n=split(f["uris"],urls,/[ \t]+/)
    for(i=1;i<=n;i++) if(official(urls[i])) known++; else if(urls[i]!="") other++
    if (!known || tolower(f["enabled"])=="no") {
        for(i=1;i<=count;i++) print lines[i]
        return
    }
    if (other || duplicates) error("混合第三方 URIs 或重复 DEB822 字段，请手动处理")
    if (tolower(f["trusted"])=="yes" || tolower(f["allow-insecure"])=="yes") error("源配置禁用了签名检查")
    ns=split(f["suites"],suites,/[ \t]+/)
    for(i=1;i<=ns;i++) {
        if(!valid_suite(suites[i])) error("未知或混合发行版套件 " suites[i])
        if(suites[i] ~ /-security$/) sec=sec (sec ? " " : "") suites[i]
        else normal=normal (normal ? " " : "") suites[i]
    }
    if (!normal && !sec) error("缺少 Suites")
    matched++
    if(normal) emit(mirror,normal)
    if(normal && sec) print ""
    if(sec) emit(security,sec)
}
format=="list" { legacy($0); next }
/^$/ { stanza(); count=0; delete lines; print ""; next }
{ lines[++count]=$0 }
END {
    if(!bad && format!="list") stanza()
    if(!bad && matched) print "yes" > matched_file
    if(bad) exit 1
}

#!/bin/env node
'use strict';

var exec = require('child_process').execFile;
var fs = require('fs');
var hostFile = {};
var ecRequest = {};
var config = {
    par: 4,
    history: 7 * 24 * 3600 * 1000,
};
var temp = new Date().getTime();
var state = {
    processes: 0,
    queue: [],
    refreshTime: temp - config.history,
    currentTime: temp,
    skipCache: 0,
};
var reg = {
    //  ip: /\b(22[0-3]|2[01][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/g,
    ip: /\b(?:22[0-3]|2[01][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}/g,
    rule: /^Rule ID: (\d+)/
};
/*
 * flags:
 *  0: incomplete
 *  1: firewall
 *  2: conditional complete
 *  4: complete
 */
var ipci = {
    '0.0.0.0': {
        ci: {},
        flag: 4,
        timestamp: 0,
        trace: ''
    },
    '1.1.1.1': {
        ci: {},
        flag: 0,
        timestamp: 0,
        trace: ''
    }
};

function ip2int(s) {
    s = s.split('.');
    return (s[0]<<24>>>0) + (s[1]<<16) + (s[2]<<8) + (s[3]*1);
}

function saveIPCI() {
    try {
        fs.writeFileSync('/home/zkp7vuq/ipci.db', JSON.stringify(ipci, null, 2));
    } catch (e) {
        fs.writeFileSync('/tmp/ipci.db', JSON.stringify(ipci, null, 2));
    }
}

// colorful console.log
function ccl(str, color) {
    if (!str)
        str = '';
    if (color)
        str = '\x1b[1;' + color + 'm' + str + '\x1b[0m';
    console.log(str);
    return str + '\n';
}

// {
//   '1.1.1.1': 'kdmzcaz1 kdmzcaz2',
//   '2.2.2.2': 'mlsiytdp1 mlsiytdp2'
// }
function openHostsFile() {
    var r = {};
    var s = fs.readFileSync('/etc/hosts', {
        encoding: 'ascii'
    });
    s.split('\n').forEach(function(line) {
        line = line.trim();
        for (var i = 0; i < line.length; i++) {
            if (line[i] == '#')
                break;
            else if (' \t'.indexOf(line[i]) >= 0) {
                var ip = line.substring(0, i);
                var t = line.indexOf('#');
                t = (t == -1) ? line.length : t;
                var host = line.substring(i + 1, t).trim();
                r[ip] = r[ip] ? r[ip] + ' ' + host : host;
                break;
            }
        }
    });
    // console.log(r);
    // manual entry
    // r['10.150.24.149']   = 'jdmzahcdrwfd';
    return r;
}

function netToHost(ip) {
    ip = ip.replace(/\.255$/, '.254');
    ip = ip.replace(/\.224$/, '.225');
    ip = ip.replace(/\.192$/, '.193');
    ip = ip.replace(/\.160$/, '.161');
    ip = ip.replace(/\.128$/, '.129');
    ip = ip.replace(/\.96$/, '.97');
    ip = ip.replace(/\.64$/, '.65');
    ip = ip.replace(/\.32$/, '.33');
    ip = ip.replace(/\.0$/, '.1');
    return ip;
}

function test(ip, cb) {
    ++state.processes;
    if (!state.skipCache && (ipci[ip] && ((!ipci[ip].timestamp) || (ipci[ip].timestamp >= state.refreshTime)))) {
        //    ccl('skipped ' + ip, 33);
        cb(0);
    } else {
        var ipt = netToHost(ip);
        ipci[ip] = {};
        ipci[ip].ci = {};
        ipci[ip].flag = (ipt == ip) ? 0 : 2;
        ipci[ip].timestamp = state.currentTime;
        var treg = new RegExp('(' + ipt + ')');
        var args = '-p pbfwrw traceroute -I ' + ipt;
        var child = exec('pbrun', args.split(' '), function(err, stdout, stderr) {
            var temp='';
            stdout = stdout.replace(/.google.com/g, '').split('\n');
            temp += ccl(ip, 34);
            for (var i = 1; i < stdout.length; i++) {
                var line = stdout[i];
                var t = line.match(reg.ip);
                if (t && (hostFile[t[0]] || (t[0] == ipt))) {
                    if (hostFile[t[0]]) {
                        ipci[ip].ci[t[0]] = 1;
                        ipci[ip].flag |= 1;
                        temp += ccl(line, 31);
                    }
                    if (t[0] == ipt) {
                        ipci[ip].flag |= 4;
                        temp += ccl(line, 32);
                    }
                } else {
                    temp += ccl(line);
                }
            }
            ipci[ip].trace = temp;
            cb();
        });
    }
}

function summaryIP(ips, showtrace) {
    Object.keys(ips).forEach(function(e) {
        var s = '';
        s += (ipci[e].flag & 1) ? 'F' : ' ';
        if (ipci[e].flag & 4) {
            s += (ipci[e].flag & 2) ? 'CC ' : 'C  ';
        } else {
            s += '   ';
        }
        s += e + '\t';
        if (ipci[e].flag & 4) {
            s += 'COMPLETE';
        }
        var a = Object.keys(ipci[e].ci);
        for (var i = 0; i < a.length; i++) {
            s += ' ' + hostFile[a[i]];
        };
        console.log(s);
    });
}

function summary(showtrace) {
    --state.processes;
    if (state.queue.length > 0) {
        test(state.queue.shift(), summary);
    } else if (!state.processes) {
        ccl('C: Complete, CC: Conditional Complete, F: Firewall.', 35);
        ecRequest.forEach(function(rule) {
            ccl('Rule ' + rule.rid + ':', 36);
            summaryIP(rule.ip, showtrace);
            ccl();
        });
        console.log(process.argv[2]);
        saveIPCI();
    }
}

(function() {
    hostFile = openHostsFile();
    var t = process.argv[2].match(reg.ip);
    if (t) {
        var temp = {};
        temp[t[0]] = 1;
        ecRequest = [{
            rid: 'dummy',
            ip: temp
        }];
        state.skipCache = 1;
    }
    ecRequest.forEach(function(e) {
        Object.keys(e.ip).forEach(function(ee) {
            state.queue.push(ee);
        });
    });
    while (state.queue.length > 0 && state.processes < config.par) {
        test(state.queue.shift(), summary);
    }
    // flow: test() -> summary()
})();

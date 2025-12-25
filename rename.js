/**
 * 更新日期：2025-12-25
 * 用法：Sub-Store 脚本操作添加
 * 修改版：节点名称修改为落地IP的归属国家代码（ISO 3166-1 alpha-2代码，如 US, CN 等）
 * 支持域名解析：如果server是域名，会先解析为IP再查询国家（使用Cloudflare DNS）
 * 支持参数：#name=前缀&flag&noCache&insecure
 * [name=] 节点添加机场名称前缀，例如 name=星霜 | 
 * [flag] 给节点前面加国旗
 * 如果IP查询失败或非IP/域名，则保留原名称
 * IP查询使用 ip-api.com API，免费但有速率限制
 * 域名解析使用 Cloudflare DNS over HTTPS (JSON format)
 */

// const inArg = $arguments;
const inArg = $arguments;
const FNAME = inArg.name == undefined ? "" : decodeURI(inArg.name);
const addflag = inArg.flag || false;

// Flag and EN maps (subset for common countries, can expand)
const FG = {
  'HK': '🇭🇰', 'MO': '🇲🇴', 'TW': '🇹🇼', 'JP': '🇯🇵', 'KR': '🇰🇷', 'SG': '🇸🇬',
  'US': '🇺🇸', 'GB': '🇬🇧', 'FR': '🇫🇷', 'DE': '🇩🇪', 'AU': '🇦🇺', 'CA': '🇨🇦',
  'NL': '🇳🇱', 'CH': '🇨🇭', 'SE': '🇸🇪', 'IE': '🇮🇪', 'RU': '🇷🇺', 'BR': '🇧🇷',
  'IN': '🇮🇳', 'ID': '🇮🇩', 'TH': '🇹🇭', 'VN': '🇻🇳', 'PH': '🇵🇭', 'MY': '🇲🇾',
  'CN': '🇨🇳' // Add more as needed
};
const EN = Object.keys(FG); // For index if needed

const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;

async function resolveDomainToIP(domain) {
  return new Promise((resolve) => {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`;
    $httpClient.get({
      url: url,
      headers: {
        'Accept': 'application/dns-json'
      }
    }, (error, response, data) => {
      if (error || response.status !== 200) {
        resolve(null);
        return;
      }
      try {
        const json = JSON.parse(data);
        if (json.Status === 0 && json.Answer && json.Answer.length > 0) {
          resolve(json.Answer[0].data);
        } else {
          resolve(null);
        }
      } catch (e) {
        resolve(null);
      }
    });
  });
}

async function getCountryCode(ip) {
  return new Promise((resolve) => {
    const url = `http://ip-api.com/json/${ip}?fields=countryCode&lang=zh-CN`;
    $httpClient.get(url, (error, response, data) => {
      if (error || response.status !== 200) {
        resolve(null);
        return;
      }
      try {
        const json = JSON.parse(data);
        resolve(json.countryCode || null);
      } catch (e) {
        resolve(null);
      }
    });
  });
}

async function getCountryCodeFromServer(server) {
  if (ipRegex.test(server)) {
    return await getCountryCode(server);
  } else {
    // Assume it's a domain, resolve to IP
    const ip = await resolveDomainToIP(server);
    if (ip) {
      return await getCountryCode(ip);
    } else {
      return null;
    }
  }
}

(async () => {
  let body = $response.body.toString();
  let lines = body.split('\n');
  let newLines = [];

  for (let line of lines) {
    let trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('[') || !trimmed.includes('=')) {
      newLines.push(line);
      continue;
    }

    // Parse Surge proxy line: "ProxyName = type, server=ip, port=443, ..."
    const eqIndex = trimmed.indexOf(' = ');
    if (eqIndex === -1) {
      newLines.push(line);
      continue;
    }

    let oldName = trimmed.substring(0, eqIndex).trim();
    let configStr = trimmed.substring(eqIndex + 3).trim();

    // Parse fields
    let fields = configStr.split(',').map(f => f.trim());
    let server = null;
    for (let field of fields) {
      if (field.startsWith('server=')) {
        server = field.substring(7);
        break;
      } else if (field.startsWith('server ')) {
        server = field.substring(7);
        break;
      }
    }

    let newName = oldName;
    if (server) {
      const countryCode = await getCountryCodeFromServer(server);
      if (countryCode) {
        newName = countryCode;
        if (FNAME) {
          newName = FNAME + (addflag ? ' ' : '') + newName;
        }
        if (addflag && FG[countryCode]) {
          newName = FG[countryCode] + ' ' + newName;
        }
      }
    }

    // Reconstruct the line
    let newLine = `${newName} = ${configStr}`;
    newLines.push(newLine);
  }

  $done({ body: newLines.join('\n') });
})();

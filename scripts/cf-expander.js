/**
 * Sub-Store 脚本
 *
 * 功能：
 * 1. 为 ArgoX 节点生成多个优选域名节点
 * 2. 从优选 IP 列表获取中国移动 IP
 * 3. 使用优选 IP 生成新节点
 *
 * 适用于：
 * VLESS / VMess / Trojan / Shadowsocks
 * v2ray-plugin WebSocket
 */

// ==================== 配置区域 ====================

// 是否保留原始节点
const KEEP_ORIGINAL = false;

// 是否只处理 ArgoX 节点
const ONLY_ARGOX_NODE = true;

// 原有优选域名
const FIXED_ENTRY_POINTS = [
  {
    server: "youxuan.cf.090227.xyz",
    port: 443,
    label: "域名-01"
  },
  {
    server: "www.shopify.com",
    port: 443,
    label: "域名-02"
  },
  {
    server: "store.ubi.com",
    port: 443,
    label: "域名-03"
  },
  {
    server: "staticdelivery.nexusmods.com",
    port: 443,
    label: "域名-04"
  },
  {
    server: "cf.877774.xyz",
    port: 443,
    label: "域名-05"
  },
  {
    server: "saas.sin.fan",
    port: 443,
    label: "域名-06"
  },
  {
    server: "bestcf.030101.xyz",
    port: 443,
    label: "域名-07"
  },
  {
    server: "cf.cloudflare.182682.xyz",
    port: 443,
    label: "域名-08"
  }
];

// 中国移动优选 IP 列表
const MOBILE_IP_URL =
  "https://bestcf.pages.dev/wetest/ipv4.txt";

// 最多添加多少个中国移动 IP
const MAX_MOBILE_IPS = 5;

// 是否启用 svip-s 高速 IP 列表
//
// 注意：该列表主要针对中国陕西移动测试，
// 不同地区、不同运营商效果可能差异很大。
// 默认关闭。
const USE_HIGH_SPEED_LIST = false;

// svip-s 项目推荐的 R2 地址
const HIGH_SPEED_IP_URL =
  "https://ips.gaoji.uk/best_ips.txt";

// 最多添加多少个高速 IP
const MAX_HIGH_SPEED_IPS = 5;


// ==================== 工具函数 ====================

function deepClone(value) {
  return JSON.parse(JSON.stringify(value));
}

function getNodePath(node) {
  if (!node || typeof node !== "object") {
    return "";
  }

  if (node["ws-opts"] && node["ws-opts"].path) {
    return node["ws-opts"].path;
  }

  if (node["xhttp-opts"] && node["xhttp-opts"].path) {
    return node["xhttp-opts"].path;
  }

  if (node["http-opts"] && node["http-opts"].path) {
    return node["http-opts"].path;
  }

  if (node["grpc-opts"] && node["grpc-opts"].grpc-service-name) {
    return node["grpc-opts"]["grpc-service-name"];
  }

  if (node["plugin-opts"] && node["plugin-opts"].path) {
    return node["plugin-opts"].path;
  }

  if (node.path) {
    return node.path;
  }

  return "";
}

function isTargetNode(node) {
  if (!ONLY_ARGOX_NODE) {
    return true;
  }

  const path = getNodePath(node);

  return typeof path === "string" &&
    path.toLowerCase().includes("/argox-");
}

function safeText(value) {
  return String(value || "")
    .replace(/\s+/g, " ")
    .replace(/[^\w\u4e00-\u9fa5|._:-]/g, "")
    .slice(0, 35);
}

function getMobileLabel(meta) {
  const text = String(meta || "");

  const match = text.match(
    /(移动|联通|电信)\s*\|\s*([A-Za-z]{2,5})/
  );

  if (match) {
    return `${match[1]}-${match[2]}`;
  }

  return safeText(text) || "移动优选";
}

function getHighSpeedLabel(meta) {
  const text = String(meta || "");

  const country = text.match(/#?([A-Z]{2,5})/);

  if (country) {
    return `高速-${country[1]}`;
  }

  return "高速优选";
}

/**
 * 解析：
 *
 * 104.17.145.155:443#微测优选 | 移动 | HKG | 104.17.145.155
 *
 * 或：
 *
 * 156.224.79.83:443#HK [优选高速 65.19ms 11.11Mbps]
 */
function parseEndpointLine(line, labelType) {
  if (!line || typeof line !== "string") {
    return null;
  }

  const rawLine = line.trim();

  if (!rawLine || rawLine.startsWith("#")) {
    return null;
  }

  const hashIndex = rawLine.indexOf("#");

  const addressPart =
    hashIndex >= 0
      ? rawLine.slice(0, hashIndex).trim()
      : rawLine;

  const meta =
    hashIndex >= 0
      ? rawLine.slice(hashIndex + 1).trim()
      : "";

  let server = "";
  let port = 443;

  // IPv6 格式：[2400::1]:443
  const ipv6Match = addressPart.match(
    /^\[([^\]]+)\](?::(\d+))?$/
  );

  if (ipv6Match) {
    server = ipv6Match[1];
    port = ipv6Match[2]
      ? Number(ipv6Match[2])
      : 443;
  } else {
    // IPv4 或域名格式：1.2.3.4:443
    const separatorIndex = addressPart.lastIndexOf(":");

    if (separatorIndex > 0) {
      server = addressPart.slice(0, separatorIndex).trim();

      const parsedPort = Number(
        addressPart.slice(separatorIndex + 1).trim()
      );

      if (Number.isInteger(parsedPort) && parsedPort > 0) {
        port = parsedPort;
      }
    } else {
      server = addressPart.trim();
    }
  }

  if (!server) {
    return null;
  }

  let label = "优选IP";

  if (labelType === "mobile") {
    label = getMobileLabel(meta);
  }

  if (labelType === "speed") {
    label = getHighSpeedLabel(meta);
  }

  return {
    server,
    port,
    label,
    meta
  };
}

function uniqueEndpoints(endpoints) {
  const result = [];
  const seen = new Set();

  for (const endpoint of endpoints) {
    if (!endpoint || !endpoint.server) {
      continue;
    }

    const key =
      `${endpoint.server.toLowerCase()}:${endpoint.port}`;

    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    result.push(endpoint);
  }

  return result;
}

function limitEndpoints(endpoints, limit) {
  return endpoints.slice(0, Math.max(0, limit));
}

/**
 * 获取远程文本。
 *
 * 如果远程列表访问失败，脚本仍然会继续生成固定优选域名节点。
 */
async function fetchText(url) {
  try {
    if (typeof fetch !== "function") {
      return "";
    }

    const request = fetch(url, {
      headers: {
        "User-Agent": "Sub-Store-ArgoX-Operator"
      }
    }).then(async response => {
      if (!response || !response.ok) {
        return "";
      }

      return await response.text();
    });

    const timeout = new Promise(resolve => {
      setTimeout(() => resolve(""), 8000);
    });

    return await Promise.race([
      request,
      timeout
    ]);
  } catch (error) {
    return "";
  }
}

async function getPreferredIPs() {
  const result = [];

  // 获取中国移动优选 IP
  const mobileText = await fetchText(MOBILE_IP_URL);

  if (mobileText) {
    const mobileEndpoints = mobileText
      .split(/\r?\n/)
      .filter(line => line.includes("移动"))
      .map(line => parseEndpointLine(line, "mobile"))
      .filter(Boolean);

    result.push(
      ...limitEndpoints(
        uniqueEndpoints(mobileEndpoints),
        MAX_MOBILE_IPS
      )
    );
  }

  // 可选：获取高速 IP
  if (USE_HIGH_SPEED_LIST) {
    const speedText = await fetchText(HIGH_SPEED_IP_URL);

    if (speedText) {
      const speedEndpoints = speedText
        .split(/\r?\n/)
        .map(line => parseEndpointLine(line, "speed"))
        .filter(Boolean);

      result.push(
        ...limitEndpoints(
          uniqueEndpoints(speedEndpoints),
          MAX_HIGH_SPEED_IPS
        )
      );
    }
  }

  return uniqueEndpoints(result);
}

function cloneWithEndpoint(node, endpoint) {
  const cloned = deepClone(node);

  const originalName =
    cloned.name || cloned.remark || "ArgoX节点";

  const originalServer =
    cloned.server || "原始地址";

  cloned.server = endpoint.server;
  cloned.port = endpoint.port || cloned.port || 443;

  cloned.name =
    `${originalName} | ${endpoint.label} | ${endpoint.server}`;

  // 某些订阅格式使用 remark
  if (cloned.remark) {
    cloned.remark =
      `${originalName} | ${endpoint.label} | ${endpoint.server}`;
  }

  // 防止出现 server:port 形式导致地址错误
  // server 必须是纯 IP 或域名
  if (String(cloned.server).includes(":")) {
    cloned.server = cloned.server
      .replace(/^\[|\]$/g, "");
  }

  return cloned;
}


// ==================== 主处理函数 ====================

async function operator(proxies = [], targetPlatform, context) {
  const endpoints = uniqueEndpoints([
    ...FIXED_ENTRY_POINTS,
    ...(await getPreferredIPs())
  ]);

  const result = [];

  for (const node of proxies) {
    if (!node || typeof node !== "object") {
      continue;
    }

    if (!isTargetNode(node)) {
      if (KEEP_ORIGINAL) {
        result.push(node);
      }

      continue;
    }

    if (KEEP_ORIGINAL) {
      result.push(node);
    }

    for (const endpoint of endpoints) {
      result.push(
        cloneWithEndpoint(node, endpoint)
      );
    }
  }

  return result;
}

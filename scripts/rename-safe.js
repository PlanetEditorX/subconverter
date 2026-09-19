/**
 * rename-safe.js
 *
 * 用法：
 *
 * xxx/scripts/rename-safe.js#name=FreeSocks
 *
 * 可选参数：
 *
 * #name=FreeSocks
 * #name=FreeSocks&flag=false
 * #name=FreeSocks&out=en
 * #name=FreeSocks&showUnknown=true
 * #name=FreeSocks&one=true
 * #name=FreeSocks&blockquic=off
 * #name=FreeSocks&group=false
 */

const DEFAULT_ARGS = {
  name: "",
  out: "cn",
  flag: true,
  fgf: " ",
  sn: "-",
  one: false,
  group: true,
  sort: true,
  showUnknown: false,
  renameRemark: false,
  blockquic: "on",
  debug: false
};

let inputArgs = {};

try {
  if (typeof $arguments !== "undefined" && $arguments) {
    inputArgs = $arguments;
  }
} catch (e) {
  inputArgs = {};
}

const args = {
  ...DEFAULT_ARGS,
  ...inputArgs
};

function decodeValue(value) {
  if (value === undefined || value === null) {
    return "";
  }

  try {
    return decodeURIComponent(String(value));
  } catch (e) {
    return String(value);
  }
}

function toBoolean(value, defaultValue = false) {
  if (value === undefined || value === null || value === "") {
    return defaultValue;
  }

  if (typeof value === "boolean") {
    return value;
  }

  return ["true", "1", "yes", "on"].includes(
    String(value).toLowerCase()
  );
}

const customName = decodeValue(args.name);
const outputType = String(args.out || "cn").toLowerCase();
const separator = decodeValue(args.fgf || " ");
const numberSeparator = decodeValue(args.sn || "-");

const addFlag = toBoolean(args.flag, true);
const removeSingleNumber = toBoolean(args.one, false);
const groupByRegion = toBoolean(args.group, true);
const sortGroups = toBoolean(args.sort, true);
const showUnknownRegion = toBoolean(args.showUnknown, false);
const renameRemark = toBoolean(args.renameRemark, false);

const blockQuic = String(
  args.blockquic === undefined ? "on" : args.blockquic
).toLowerCase();

const debug = toBoolean(args.debug, false);


// 常见地区识别规则
// 不使用 g 标记，避免 RegExp.lastIndex 导致匹配异常
const REGION_RULES = [
  {
    key: "HK",
    zh: "香港",
    en: "HK",
    flag: "🇭🇰",
    regex: /香港|Hong\s*Kong|Hongkong|HKG|\bHK\b|🇭🇰/i
  },
  {
    key: "MO",
    zh: "澳门",
    en: "MO",
    flag: "🇲🇴",
    regex: /澳门|Macau|Macao|\bMO\b|🇲🇴/i
  },
  {
    key: "TW",
    zh: "台湾",
    en: "TW",
    flag: "🇹🇼",
    regex: /台湾|台北|Taiwan|Taipei|\bTW\b|🇹🇼/i
  },
  {
    key: "JP",
    zh: "日本",
    en: "JP",
    flag: "🇯🇵",
    regex: /日本|东京|大阪|Japan|Tokyo|Osaka|\bJP\b|🇯🇵/i
  },
  {
    key: "KR",
    zh: "韩国",
    en: "KR",
    flag: "🇰🇷",
    regex: /韩国|首尔|春川|Korea|Seoul|Chuncheon|\bKR\b|🇰🇷/i
  },
  {
    key: "SG",
    zh: "新加坡",
    en: "SG",
    flag: "🇸🇬",
    regex: /新加坡|狮城|Singapore|\bSG\b|🇸🇬/i
  },
  {
    key: "US",
    zh: "美国",
    en: "US",
    flag: "🇺🇸",
    regex: /美国|纽约|洛杉矶|西雅图|硅谷|United\s*States|USA|Los\s*Angeles|\bUS\b|🇺🇸/i
  },
  {
    key: "GB",
    zh: "英国",
    en: "GB",
    flag: "🇬🇧",
    regex: /英国|伦敦|United\s*Kingdom|London|\bUK\b|\bGB\b|🇬🇧/i
  },
  {
    key: "DE",
    zh: "德国",
    en: "DE",
    flag: "🇩🇪",
    regex: /德国|法兰克福|Germany|Frankfurt|\bDE\b|🇩🇪/i
  },
  {
    key: "FR",
    zh: "法国",
    en: "FR",
    flag: "🇫🇷",
    regex: /法国|巴黎|France|Paris|\bFR\b|🇫🇷/i
  },
  {
    key: "AU",
    zh: "澳大利亚",
    en: "AU",
    flag: "🇦🇺",
    regex: /澳大利亚|澳洲|悉尼|墨尔本|Australia|Sydney|Melbourne|\bAU\b|🇦🇺/i
  },
  {
    key: "CA",
    zh: "加拿大",
    en: "CA",
    flag: "🇨🇦",
    regex: /加拿大|Canada|\bCA\b|🇨🇦/i
  },
  {
    key: "RU",
    zh: "俄罗斯",
    en: "RU",
    flag: "🇷🇺",
    regex: /俄罗斯|莫斯科|Russia|Moscow|\bRU\b|🇷🇺/i
  },
  {
    key: "IN",
    zh: "印度",
    en: "IN",
    flag: "🇮🇳",
    regex: /印度|孟买|India|Mumbai|\bIN\b|🇮🇳/i
  },
  {
    key: "TH",
    zh: "泰国",
    en: "TH",
    flag: "🇹🇭",
    regex: /泰国|曼谷|Thailand|Bangkok|\bTH\b|🇹🇭/i
  },
  {
    key: "VN",
    zh: "越南",
    en: "VN",
    flag: "🇻🇳",
    regex: /越南|Vietnam|\bVN\b|🇻🇳/i
  },
  {
    key: "MY",
    zh: "马来西亚",
    en: "MY",
    flag: "🇲🇾",
    regex: /马来西亚|Malaysia|\bMY\b|🇲🇾/i
  },
  {
    key: "ID",
    zh: "印度尼西亚",
    en: "ID",
    flag: "🇮🇩",
    regex: /印度尼西亚|印尼|雅加达|Indonesia|Jakarta|\bID\b|🇮🇩/i
  },
  {
    key: "NL",
    zh: "荷兰",
    en: "NL",
    flag: "🇳🇱",
    regex: /荷兰|阿姆斯特丹|Netherlands|Amsterdam|\bNL\b|🇳🇱/i
  }
];

function detectRegion(name) {
  const text = String(name || "");

  for (const region of REGION_RULES) {
    if (region.regex.test(text)) {
      return region;
    }
  }

  return {
    key: "OTHER",
    zh: "其他",
    en: "OTHER",
    flag: "",
    regex: null
  };
}

function getRegionText(region) {
  if (region.key === "OTHER" && !showUnknownRegion) {
    return "";
  }

  if (outputType === "en" || outputType === "us") {
    return region.en;
  }

  if (outputType === "gq" || outputType === "flag") {
    return region.flag;
  }

  return region.zh;
}

function getNodeOriginalName(node, index) {
  return String(
    node.name ||
    node.remark ||
    node.server ||
    `节点-${index + 1}`
  );
}

function addBlockQuic(node) {
  if (blockQuic === "on") {
    node["block-quic"] = "on";
  } else if (blockQuic === "off") {
    node["block-quic"] = "off";
  }

  return node;
}

function buildNodeName(item, sequence, total) {
  const originalName = item.originalName;
  const region = item.region;
  const regionText = getRegionText(region);

  const noNumber =
    removeSingleNumber && total === 1;

  const numberText = noNumber
    ? ""
    : String(sequence).padStart(2, "0");

  const suffix = regionText
    ? `${regionText}${numberSeparator}${numberText}`
    : numberText;

  let baseName = customName || originalName;

  // 有自定义名称时，可为已识别地区添加国旗
  if (
    customName &&
    addFlag &&
    region.flag &&
    outputType !== "flag" &&
    outputType !== "gq"
  ) {
    baseName = `${region.flag}${separator}${baseName}`;
  }

  if (!suffix) {
    return baseName;
  }

  if (!customName && !regionText) {
    return `${baseName}${numberSeparator}${numberText}`;
  }

  if (!regionText && customName) {
    return `${baseName}${numberSeparator}${numberText}`;
  }

  return `${baseName}${separator}${suffix}`;
}

function operator(proxies = []) {
  const items = [];
  const groups = new Map();

  // 第一遍：识别地区并建立分组
  proxies.forEach((node, index) => {
    if (!node || typeof node !== "object") {
      return;
    }

    const originalName = getNodeOriginalName(node, index);
    const region = detectRegion(originalName);

    const groupKey = groupByRegion
      ? region.key
      : "ALL";

    const item = {
      node,
      index,
      originalName,
      region,
      groupKey
    };

    items.push(item);

    if (!groups.has(groupKey)) {
      groups.set(groupKey, []);
    }

    groups.get(groupKey).push(item);
  });

  let orderedItems = [];

  if (sortGroups) {
    for (const groupItems of groups.values()) {
      orderedItems.push(...groupItems);
    }
  } else {
    orderedItems = [...items].sort(
      (a, b) => a.index - b.index
    );
  }

  // 统计每组节点数量
  const groupTotals = new Map();

  for (const item of orderedItems) {
    groupTotals.set(
      item.groupKey,
      (groupTotals.get(item.groupKey) || 0) + 1
    );
  }

  const groupCounters = new Map();

  // 第二遍：重命名
  for (const item of orderedItems) {
    const currentNumber =
      (groupCounters.get(item.groupKey) || 0) + 1;

    groupCounters.set(
      item.groupKey,
      currentNumber
    );

    const total =
      groupTotals.get(item.groupKey) || 1;

    item.node.name = buildNodeName(
      item,
      currentNumber,
      total
    );

    if (
      renameRemark &&
      typeof item.node.remark === "string"
    ) {
      item.node.remark = item.node.name;
    }

    addBlockQuic(item.node);

    if (debug) {
      console.log(
        `${item.originalName} => ${item.node.name}`
      );
    }
  }

  return orderedItems.map(item => item.node);
}

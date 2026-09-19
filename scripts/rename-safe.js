/**
 * rename-safe.js
 *
 * =========================
 * 使用方法
 * =========================
 *
 * 1. 普通重命名：
 *
 * xxx/scripts/rename-safe.js#name=VPS
 *
 * 输出示例：
 *
 * 🇺🇸 美国-01 | VPS
 * 🇺🇸 美国-02 | VPS
 * 🇭🇰 香港-01 | VPS
 * 🌐 其他-01 | VPS
 *
 *
 * 2. 自定义未知地区名称：
 *
 * xxx/scripts/rename-safe.js#name=FreeSocks&other=免费
 *
 * 输出：
 *
 * 🎉 免费-01 | FreeSocks
 * 🎉 免费-02 | FreeSocks
 *
 *
 * 3. 自定义地区 Emoji：
 *
 * xxx/scripts/rename-safe.js#name=FreeSocks&other=低倍率&otherEmoji=🎯
 *
 * 输出：
 *
 * 🎯 低倍率-01 | FreeSocks
 *
 *
 * 4. 使用英文地区名：
 *
 * xxx/scripts/rename-safe.js#name=VPS&out=en
 *
 * 输出：
 *
 * 🇺🇸 US-01 | VPS
 * 🇭🇰 HK-01 | VPS
 *
 *
 * 5. 不添加 Emoji：
 *
 * xxx/scripts/rename-safe.js#name=VPS&flag=false
 *
 * 输出：
 *
 * 美国-01 | VPS
 * 香港-01 | VPS
 *
 *
 * 6. 单节点隐藏 -01：
 *
 * xxx/scripts/rename-safe.js#name=VPS&one=true
 *
 *
 * 7. 关闭 block-quic：
 *
 * xxx/scripts/rename-safe.js#name=VPS&blockquic=off
 *
 *
 * =========================
 * 参数说明
 * =========================
 *
 * name：
 *   竖线后面的自定义名称，例如 VPS、FreeSocks。
 *
 * other：
 *   无法识别地区时显示的名称，默认是“其他”。
 *
 * otherEmoji：
 *   无法识别地区时使用的 Emoji。
 *
 * out：
 *   cn  = 中文地区名，默认
 *   en  = 英文国家代码
 *   flag = 只显示国旗
 *
 * flag：
 *   是否显示国旗，默认 true。
 *
 * fgf：
 *   名称之间的分隔符，默认空格。
 *
 * sn：
 *   编号分隔符，默认 -。
 *
 * one：
 *   只有一个节点时是否隐藏 -01，默认 false。
 *
 * group：
 *   是否按照地区分别编号，默认 true。
 *
 * sort：
 *   是否按照地区排序，默认 true。
 *
 * blockquic：
 *   on    添加 block-quic
 *   off   设置 block-quic 为 off
 *   keep  保持原配置
 *
 * renameRemark：
 *   是否同步修改 remark 字段，默认 false。
 */


// =========================
// 默认参数
// =========================

const DEFAULT_ARGS = {
  name: "",
  out: "cn",
  flag: true,
  fgf: " ",
  sn: "-",
  one: false,
  group: true,
  sort: true,
  other: "其他",
  otherEmoji: "",
  renameRemark: false,
  blockquic: "on",
  debug: false
};


// =========================
// 读取 Sub-Store 参数
// =========================

let inputArgs = {};

try {
  if (typeof $arguments !== "undefined" && $arguments) {
    inputArgs = $arguments;
  }
} catch (error) {
  inputArgs = {};
}

const args = {
  ...DEFAULT_ARGS,
  ...inputArgs
};


// =========================
// 工具函数
// =========================

function decodeValue(value) {
  if (value === undefined || value === null) {
    return "";
  }

  try {
    return decodeURIComponent(String(value));
  } catch (error) {
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

  return [
    "true",
    "1",
    "yes",
    "on"
  ].includes(String(value).toLowerCase());
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function getFirstArgument(keys, defaultValue = "") {
  for (const key of keys) {
    if (hasOwn(inputArgs, key)) {
      return inputArgs[key];
    }
  }

  return defaultValue;
}


// =========================
// 参数处理
// =========================

const customName = decodeValue(
  getFirstArgument(["name"], "")
);

const outputType = String(
  getFirstArgument(["out"], "cn")
).toLowerCase();

const separator = decodeValue(
  getFirstArgument(["fgf"], " ")
);

const numberSeparator = decodeValue(
  getFirstArgument(["sn"], "-")
);

const customOtherName = decodeValue(
  getFirstArgument(
    ["other", "unknown", "customRegion"],
    "其他"
  )
);

const customOtherEmoji = decodeValue(
  getFirstArgument(
    ["otherEmoji", "unknownEmoji", "customEmoji"],
    ""
  )
);

const addFlag = toBoolean(
  getFirstArgument(["flag"], true),
  true
);

const removeSingleNumber = toBoolean(
  getFirstArgument(["one"], false),
  false
);

const groupByRegion = toBoolean(
  getFirstArgument(["group"], true),
  true
);

const sortGroups = toBoolean(
  getFirstArgument(["sort"], true),
  true
);

const renameRemark = toBoolean(
  getFirstArgument(["renameRemark"], false),
  false
);

const blockQuic = String(
  getFirstArgument(["blockquic"], "on")
).toLowerCase();

const debug = toBoolean(
  getFirstArgument(["debug"], false),
  false
);


// =========================
// 自定义地区 Emoji
// =========================

const OTHER_EMOJI_MAP = {
  "其他": "🌐",
  "其它": "🌐",
  "免费": "🎉",
  "优选": "🚀",
  "高速": "⚡",
  "低倍率": "🎯",
  "高倍率": "🔥",
  "备用": "🔁",
  "自定义": "🛠️",
  "测试": "🧪",
  "临时": "⏱️",
  "移动": "📱",
  "联通": "🔗",
  "电信": "📡",
  "香港": "🇭🇰",
  "日本": "🇯🇵",
  "美国": "🇺🇸",
  "新加坡": "🇸🇬",
  "韩国": "🇰🇷"
};

function getOtherEmoji() {
  if (customOtherEmoji) {
    return customOtherEmoji;
  }

  if (OTHER_EMOJI_MAP[customOtherName]) {
    return OTHER_EMOJI_MAP[customOtherName];
  }

  return "📍";
}


// =========================
// 地区识别规则
// =========================

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
    zh: customOtherName,
    en: "OTHER",
    flag: getOtherEmoji(),
    regex: null
  };
}

function getRegionText(region) {
  if (region.key === "OTHER") {
    return customOtherName;
  }

  if (
    outputType === "en" ||
    outputType === "us"
  ) {
    return region.en;
  }

  if (
    outputType === "flag" ||
    outputType === "gq"
  ) {
    return region.flag;
  }

  return region.zh;
}

function getRegionEmoji(region) {
  if (region.key === "OTHER") {
    return getOtherEmoji();
  }

  return region.flag;
}

function getNodeOriginalName(node, index) {
  return String(
    node.name ||
    node.remark ||
    node.server ||
    `节点-${index + 1}`
  );
}


// =========================
// 名称生成
// =========================

function buildNodeName(item, sequence, total) {
  const region = item.region;

  const hideNumber =
    removeSingleNumber && total === 1;

  const numberText = hideNumber
    ? ""
    : `${numberSeparator}${String(sequence).padStart(2, "0")}`;

  const regionText = getRegionText(region);
  const emoji = getRegionEmoji(region);

  let emojiText = "";

  // out=flag 时，地区名称本身就是 Emoji
  if (
    addFlag &&
    emoji &&
    outputType !== "flag" &&
    outputType !== "gq"
  ) {
    emojiText = `${emoji}${separator}`;
  }

  let result =
    `${emojiText}${regionText}${numberText}`;

  // 保持格式：地区-01 | 自定义名称
  if (customName) {
    result += ` | ${customName}`;
  }

  return result;
}


// =========================
// block-quic 处理
// =========================

function applyBlockQuic(node) {
  if (blockQuic === "on") {
    node["block-quic"] = "on";
  }

  if (blockQuic === "off") {
    node["block-quic"] = "off";
  }

  // keep：保持原节点配置不变
  return node;
}


// =========================
// 排序辅助
// =========================

function getRegionRank(regionKey) {
  if (regionKey === "OTHER") {
    return 999;
  }

  const index = REGION_RULES.findIndex(
    item => item.key === regionKey
  );

  return index === -1 ? 998 : index;
}


// =========================
// Sub-Store 主函数
// =========================

function operator(proxies = []) {
  const items = [];
  const groups = new Map();

  // 第一阶段：识别地区和分组
  proxies.forEach((node, index) => {
    if (!node || typeof node !== "object") {
      return;
    }

    const originalName =
      getNodeOriginalName(node, index);

    const region =
      detectRegion(originalName);

    const groupKey =
      groupByRegion ? region.key : "ALL";

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
    const groupArray =
      Array.from(groups.entries());

    groupArray.sort((a, b) => {
      const regionA = a[1][0].region;
      const regionB = b[1][0].region;

      const rankA = getRegionRank(regionA.key);
      const rankB = getRegionRank(regionB.key);

      if (rankA !== rankB) {
        return rankA - rankB;
      }

      return a[1][0].index - b[1][0].index;
    });

    for (const [, groupItems] of groupArray) {
      orderedItems.push(...groupItems);
    }
  } else {
    orderedItems = [...items].sort(
      (a, b) => a.index - b.index
    );
  }

  // 统计每组数量
  const groupTotals = new Map();

  for (const item of orderedItems) {
    const current =
      groupTotals.get(item.groupKey) || 0;

    groupTotals.set(
      item.groupKey,
      current + 1
    );
  }

  // 各组编号
  const groupCounters = new Map();

  for (const item of orderedItems) {
    const current =
      (groupCounters.get(item.groupKey) || 0) + 1;

    groupCounters.set(
      item.groupKey,
      current
    );

    const total =
      groupTotals.get(item.groupKey) || 1;

    item.node.name =
      buildNodeName(
        item,
        current,
        total
      );

    if (
      renameRemark &&
      typeof item.node.remark === "string"
    ) {
      item.node.remark = item.node.name;
    }

    applyBlockQuic(item.node);

    if (debug) {
      console.log(
        `${item.originalName} => ${item.node.name}`
      );
    }
  }

  return orderedItems.map(
    item => item.node
  );
}

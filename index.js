var bsv = require('bsv')
// Extend BSV
require('bitcoin-ibe')
var CryptoJS = require('crypto-js')
const DEBUG = false

/*
BitDiary

Basic Function:
    Constructor -   Create a diary instance
    readDiary   -   Read a single diary with ViewKey from remote node
    readDiaries -   Read all diaries from remote node
    getDiaries  -   Get decrpyted diaries
    getDiaryUpdateOutput    -   Create a diary output (for building transaction)

Advanced Function:
    getEditKey  -   Get EditKey for specified index
    getCrypticPrefix    -   Get CrypticPrefix for indexing
    getEncryptedDiaries -   Get raw diaries data
    readDiariesFromCache    -   read diaries from parameters(raw diaries data)

Utilities:
    AESDecrypt  -   Do decryption
    AESEncrypt  -   Do encryption
    getDecryptResult    -   Diary ciphertext decrypt
    editKey -   Create EditKey
    getSignature    -   Generate ECDSA secp256k1 signature with bitcoin library
    verifySignature -   Verify ECDSA secp256k1 signature with bitcoin library

*/

function BitDiary(privkey, prefix) {
    this.prefix = "BitDiary"
    this.privkey = bsv.PrivateKey(privkey)
    this.newEditKey = null
    this.newIndex = 0
    this.diaries = []
    this.encryptedDiaries = []
    this.status = BitDiary.STATUS.INIT
    this.prefix = prefix || "BitDiary"
}

BitDiary.STATUS = {
    INIT: 0,
    HASLAST: 1,
    ALLREAD: 2
}

BitDiary.prototype.getDiaryUpdateOutput = function (diary, EditKey) {
    EditKey = EditKey || this.newEditKey
    var crypticPrefix = this.getCrypticPrefix(EditKey.publicKey)

    var encDiary = BitDiary.AESEncrypt(diary, EditKey.publicKey)
    var diaryhashbuf = bsv.deps.Buffer.from(diary)
    var signature = BitDiary.getSignature(diaryhashbuf, EditKey)

    var script = new bsv.Script.buildDataOut(crypticPrefix)
    script.add(bsv.deps.Buffer.from(encDiary))
    script.add(bsv.deps.Buffer.from(signature))
    return new bsv.Transaction.Output({
        satoshis: 0,
        script: script
    })
}

BitDiary.prototype.incCurKey = function () {
    this.newIndex++
}

BitDiary.prototype.getEditKey = function (index) {
    return BitDiary.editKey(this.privkey, String(index))
}

BitDiary.prototype.getCrypticPrefix = function (pubkey) {
    return bsv.crypto.Hash.sha256(bsv.deps.Buffer.from(this.prefix + pubkey.toString())).toString('base64')
}

BitDiary.prototype.readDiariesFromCache = function (cachedDiaries) {
    var diaries = JSON.parse(cachedDiaries)
    if (!Array.isArray(diaries)) return
    var verfied = diaries.every((entry, index) => {
        if (!entry) return false
        var viewKey = BitDiary.editKey(this.privkey, String(index)).publicKey
        return BitDiary.verifySignature(BitDiary.getDecryptResult(entry.diary, viewKey), entry.sigstr, viewKey)
    })
    if (verfied) this.encryptedDiaries = diaries
}

BitDiary.prototype.readDiaries = async function (index) {
    if (this.privkey == null || this.privkey == "") {
        throw new Error("Invalid Privkey")
    }

    // Read specific diary
    if(index){
        var editKey = BitDiary.editKey(this.privkey, String(index))
        if(DEBUG) console.log(index + ":" + editKey)
        var diaryRecord = await this.readDiary(curVKey.publicKey)
        if (diaryRecord.length > 0) {
            this.encryptedDiaries[index] = diaryRecord
            this.diaries[index] = diaryRecord[0]
            var plaintext = BitDiary.getDecryptResult(diaryRecord[0].diary, editKey.publicKey)
            if(DEBUG) console.log(index + ":" + plaintext)
            return true
        }
        return false
    }

    // binary search algorithm
    // by doing binary search, we can locate the last entry quickly, so we can do push before we read everything

    var keyIndex = this.diaries.length
    var lastKnown = this.diaries.filter(diary => diary.time != null).length > 0 ? this.diaries.filter(diary => diary.time != null).length - 1 : -1
    var boundary = -1
    var hasLatest = false
    do {
        var curVKey = BitDiary.editKey(this.privkey, String(keyIndex))
        if(DEBUG) console.log(keyIndex + ":" + curVKey)
        var diaryRecord = await this.readDiary(curVKey.publicKey)
        if (diaryRecord.length > 0) {
            this.encryptedDiaries[keyIndex] = diaryRecord
            this.diaries[keyIndex] = diaryRecord[0]
            var plaintext = BitDiary.getDecryptResult(diaryRecord[0].diary, curVKey.publicKey)
            if(DEBUG) console.log(keyIndex + ":" + plaintext)
        }

        // 指数递进，随后二分确定最新日志及curVKey
        // 确保可以在短时间内可以写新日记
        // 随后加载所有日志
        if(DEBUG) console.log(`Searching Index: ${keyIndex} lastKnown: ${lastKnown} boundary: ${boundary}`)
        if (!hasLatest) {
            // 不知道最新的日志是什么，还在搜索
            if(DEBUG) console.log("boundary still unknow")
            if (diaryRecord.length > 0) {
                // 命中了，更新lastknown
                if(DEBUG) console.log("update lastknown")
                lastKnown = keyIndex
                if (boundary == -1) {
                    // 还不知道上限，指数递进
                    if(DEBUG) console.log("binary increase search index")
                    keyIndex = (keyIndex + 1) * 2 - 1
                } else {
                    // 已经知道范围上限，区间内指数递进缩小搜索范围
                    if(DEBUG) console.log("as we knows boundary, closing the range to last one")
                    if (boundary - keyIndex == 1) {
                        // 找到了尾部
                        if(DEBUG) console.log("we have the last one")
                        hasLatest = true
                        keyIndex = keyIndex + 1
                        this.newEditKey = BitDiary.editKey(this.privkey, String(keyIndex))
                        this.newIndex = keyIndex
                        this.status = BitDiary.STATUS.HASLAST
                    } else {
                        // 前进到二分之一处
                        keyIndex = lastKnown + Math.floor((boundary - lastKnown) / 2)
                    }
                }
            } else {
                // 未命中，说明达到了上限
                if(DEBUG) console.log("index out of boundary")
                boundary = keyIndex
                if (keyIndex - lastKnown == 1) {
                    // 找到了尾部
                    if(DEBUG) console.log("we have the last one")
                    hasLatest = true
                    this.newEditKey = BitDiary.editKey(this.privkey, String(keyIndex))
                    this.newIndex = keyIndex
                    this.status = BitDiary.STATUS.HASLAST
                } else {
                    // 后退到二分之一处
                    keyIndex = lastKnown + Math.floor((boundary - lastKnown) / 2)
                }
            }
        }
        if (hasLatest) {
            // 已经知道最新了，那么进行逐一回退搜索
            if(DEBUG) console.log("as we know the last, read entries one by one now")
            while (keyIndex > 0 && this.diaries[keyIndex - 1] != undefined && this.diaries[keyIndex - 1].time != null) {
                // 跳过已经知道的日志
                if(DEBUG) console.log(`Skipping already known ${keyIndex - 1}`)
                keyIndex = keyIndex - 1
            }
            keyIndex = keyIndex - 1
        }
        if(DEBUG) console.log(`Next index :${keyIndex}`)
        this.loading = !this.loading
    } while (keyIndex > 0)

    this.status = BitDiary.STATUS.ALLREAD
    //if(DEBUG) console.log("缓存日志")
    //localStorage.setItem("cachedDiaries", JSON.stringify(this.diaries))
    return true
}

BitDiary.prototype.getEncryptedDiaries = function () {
    return this.encryptedDiaries
}

BitDiary.prototype.getDiaries = function () {
    return this.encryptedDiaries.map((diaryRecord, index) => {
        return diaryRecord.map(diary => {
            return {
                block: diary.blk,
                time: diary.time,
                diary: BitDiary.getDecryptResult(diary.diary, BitDiary.editKey(this.privkey, String(index)).publicKey)
            }
        })
    })
}

BitDiary.prototype.readDiary = function (ViewKey) {
    var crypticPrefix = this.getCrypticPrefix(ViewKey)
    var query = {
        "v": 3,
        "q": {
            "find": { "out.s1": crypticPrefix },
        },
        "r": {
            "f": "[ .[] | {diary: .out[0].s2, ldiary: .out[0].ls2, sigstr: .out[0].s3, txid: .tx.h, blk:.blk.i, time:.blk.t} ]"
        }
    }
    var b64 = btoa(JSON.stringify(query));
    var myendpoint = window["endpoint"] || "https://genesis.bitdb.network/q/1FnauZ9aUH2Bex6JzdcV4eNX7oLSSEbxtN/"
    var url = myendpoint + b64;
    var header = {
        headers: { key: ['159bcdKY4spcahzfTZhBbFBXrTWpoh4rd3'] }
    };
    return fetch(url, header)
        .then(r => r.json())
        .then(r => r.u.concat(r.c.sort((a, b) => b.blk - a.blk)))
        .then(r => r.reverse())
        .then(r => { r.forEach(entry => entry.diary = entry.diary || entry.ldiary); return r })
        .then(r => r.filter(entry => BitDiary.verifySignature(BitDiary.getDecryptResult(entry.diary, ViewKey), entry.sigstr, ViewKey)))
}


/*
    Utilities
*/

BitDiary.AESDecrypt = function (ciphertext, vaultKey) {
    var keybuf = bsv.crypto.Hash.sha256(vaultKey.toBuffer())
    var key = CryptoJS.enc.Hex.parse(keybuf.slice(0, 8).toString('hex'));
    var iv = CryptoJS.enc.Hex.parse(keybuf.slice(8, 16).toString('hex'));
    var decrypt = CryptoJS.AES.decrypt(ciphertext, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    var decryptedStr = decrypt.toString(CryptoJS.enc.Utf8);
    return decryptedStr.toString();
}

BitDiary.AESEncrypt = function (plaintext, vaultKey) {
    var keybuf = bsv.crypto.Hash.sha256(vaultKey.toBuffer())
    var key = CryptoJS.enc.Hex.parse(keybuf.slice(0, 8).toString('hex'));
    var iv = CryptoJS.enc.Hex.parse(keybuf.slice(8, 16).toString('hex'));
    var srcs = CryptoJS.enc.Utf8.parse(plaintext);
    var encrypted = CryptoJS.AES.encrypt(srcs, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    return CryptoJS.enc.Base64.stringify(encrypted.ciphertext)
}

BitDiary.getDecryptResult = function (ciphertext, key) {
    try {
        return BitDiary.AESDecrypt(ciphertext, key)
    } catch (err) {
        return err
    }
}

BitDiary.editKey = function (IDKey, vault) {
    return bsv.PrivateKey(bsv.crypto.Hash.sha256sha256(bsv.PrivateKey(IDKey).childKey(String(vault)).toBuffer()).toString('hex'))
}

BitDiary.getSignature = function (content, privateKey) {
    var hashbuf = bsv.crypto.Hash.sha256(bsv.deps.Buffer.from(content))
    return bsv.crypto.ECDSA.sign(hashbuf, privateKey).toDER().toString('base64')
}

BitDiary.verifySignature = function (content, sigstr, publicKey) {
    var hashbuf = bsv.crypto.Hash.sha256(bsv.deps.Buffer.from(content))
    var signature = bsv.crypto.Signature.fromDER(bsv.deps.Buffer.from(sigstr, 'base64'))
    return bsv.crypto.ECDSA.verify(hashbuf, signature, publicKey)
}

module.exports = BitDiary

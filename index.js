/**
 * node加密模块
 * @date 2018-06-19
 * @author Markey
 */
const crypto = require('crypto')
const fs = require('fs')
/**
 * 生成AES key及iv
 * @param  {Number} keyLength [AES key长度，单位：比特位]
 * @return {Object}           [key及iv都是Buffer]
 */
function genAESKeyAndIv(keyLength = 256) {
  const res = {
    key: getRandomBytes(keyLength/8),
    iv: getRandomBytes(128/8),
  }
  return res
}
/**
 * AES加密
 * @param  {Buffer|String}    content      [要加密的内容，可以为Buffer或字符串]
 * @param  {String} options.algorithm      [加密算法]
 * @param  {Buffer} options.key            [AES密钥]
 * @param  {Buffer} options.iv             [AES初始化向量]
 * @param  {String} options.inputEncoding  [要加密内容编码，默认为buffer，即'']
 * @param  {String} options.outputEncoding [加密出的内容编码，可为base64、hex、latin1]
 * @return {String}                        [加密后的内容]
 */
function aesEncrypt(content, {
  algorithm,
  key,
  iv,
  inputEncoding = '',
  outputEncoding = 'base64'
}) {
  const cipheriv = crypto.createCipheriv(algorithm, key, iv)
  let encryptedData = cipheriv.update(content, inputEncoding, outputEncoding)
  encryptedData += cipheriv.final(outputEncoding)
  return encryptedData
}
/**
 * AES解密
 * @param  {Buffer|String} content         [要加密的内容，可以为Buffer或字符串]
 * @param  {String} options.algorithm      [解密算法]
 * @param  {Buffer} options.key            [AES密钥]
 * @param  {Buffer} options.iv             [AES初始化向量]
 * @param  {String} options.inputEncoding  [要解密内容的编码，默认为base64，可为hex或latin1]
 * @param  {String} options.outputEncoding [解密后内容的编码，默认为utf8，可为latin1、ascii]
 * @return {String}                        [解密后的内容]
 */
function aesDecrypt(content, {
  algorithm,
  key,
  iv,
  inputEncoding = 'base64',
  outputEncoding = 'utf8'
}) {
  const decipheriv = crypto.createDecipheriv(algorithm, key, iv)
  let decryptedData = decipheriv.update(content, inputEncoding, outputEncoding)
  decryptedData += decipheriv.final(outputEncoding)
  return decryptedData
}
/**
 * RSA加密
 * @param  {Buffer} content                [待加密的内容]
 * @param  {String} options.splitBar       [分割线，用来标识待加密的内容及随机填充的内容]
 * @param  {String} options.pubKeyPath     [公钥存放的路径]
 * @param  {Number} options.keyLength      [公钥的长度]
 * @param  {String} options.outputEncoding [输出内容的编码，默认为base64]
 * @return {String}
 */
function rsaEncrypt(content, {
  splitBar,
  pubKeyPath,
  keyLength,
  outputEncoding = 'base64'
}) {
  // 分割线，用于告知服务端如何区分要解密的内容与填充的内容
  const splitBarBuffer = Buffer.from(splitBar)
  // 由于RSA算法有长度限制，因此需要填补待加密的内容
  const restLength = keyLength/8 - splitBarBuffer.length - content.length
  // console.log('\n需要填充的字节数：', restLength, '已有内容的字节数', content.length)
  // 填充随机内容
  // 经验证使用crypto.randomBytes生成的Buffer不准确，因此采用自己开发的getRandomBytes方法替代
  const contentNeedCrypt = Buffer.concat([getRandomBytes(restLength), splitBarBuffer, content])
  // console.log('填充后总内容字节数：', contentNeedCrypt.length)
  // 开始加密
  const res = crypto.publicEncrypt({
    key: fs.readFileSync(pubKeyPath),
    padding: crypto.constants.RSA_NO_PADDING
  }, contentNeedCrypt)
  return res.toString(outputEncoding)
}
/**
 * RSA解密
 * @param  {String} content                [待解密的内容]
 * @param  {String} options.splitBar       [分割线，用来标识待加密的内容及随机填充的内容]
 * @param  {String} options.priKeyPath     [私钥的存放路径]
 * @param  {String} options.outputEncoding [输出内容编码，默认为utf8]
 * @param  {String} options.inputEncoding  [输入内容的编码，默认为base64]
 * @return {String}
 */
function rsaDecrypt(content, {
  splitBar,
  priKeyPath,
  outputEncoding = 'utf8',
  inputEncoding = 'base64'
}) {
  // console.log(`rsa decrypt content：${content}`)
  // 由于要解密的内容可能不是buffer，因此需要先将其转为buffer
  const contentNeedDecrypt = Buffer.from(content, inputEncoding)
  const decryptedData = crypto.privateDecrypt({
    key: fs.readFileSync(priKeyPath),
    padding: crypto.constants.RSA_NO_PADDING
  }, contentNeedDecrypt).toString(outputEncoding)
  // console.log(decryptedData)
  const res = decryptedData.split(splitBar)[1]
  // console.log(res)
  return res
}
/**
 * 获取指定字节的Buffer
 * 为何不用crypto.randomBytes？因为crypto.randomBytes生成的Buffer长度并不准确，可能是由于生成的Buffer随机的字符串中包含特殊字符导致，因此该方法只使用英文字母，因为英文字母在utf8编码下一个字符就是一字节
 * @param  {Number} size [生成的Buffer的字节数]
 * @return {Buffer}
 */
function getRandomBytes(size) {
  const buffer = Buffer.alloc(size)
  const str = getRandomString(size)
  // 还必须用这种方式写入Buffer，不能直接返回Buffer.from(str)，生成的Buffer字节数也不准确
  buffer.write(str)
  return buffer
}
/**
 * 获取指定长度的随机字符串：内容只由英文字符构成，防止特殊符号不同编码下乱码及错位
 * @param  {Number} length [字符串长度]
 * @return {String}
 */
function getRandomString(length) {
  const letters = 'abcdefghijklmnopqrstuvwxyz'
  let str = ''
  let count = 0
  while(count < length) {
    str += letters[Math.floor(Math.random() * 26)]
    count++
  }
  return str
}


module.exports = {
  genAESKeyAndIv,
  aesEncrypt,
  aesDecrypt,
  rsaEncrypt,
  rsaDecrypt,
  getRandomBytes,
  getRandomString
}


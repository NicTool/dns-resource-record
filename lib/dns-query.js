import { createSocket } from 'node:dgram'
import { createConnection } from 'node:net'

export function dnsQueryUDP(host, port, queryBuf, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const socket = createSocket('udp4')
    const timer = setTimeout(() => {
      socket.close()
      reject(new Error(`DNS query timed out (${host}:${port})`))
    }, timeout)
    socket.on('message', (msg) => {
      clearTimeout(timer)
      socket.close()
      resolve(msg)
    })
    socket.on('error', (err) => {
      clearTimeout(timer)
      socket.close()
      reject(err)
    })
    socket.send(queryBuf, port, host, (err) => {
      if (err) {
        clearTimeout(timer)
        socket.close()
        reject(err)
      }
    })
  })
}

export function dnsQueryTCP(host, port, queryBuf, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const conn = createConnection({ host, port })
    const timer = setTimeout(() => {
      conn.destroy()
      reject(new Error(`DNS TCP query timed out (${host}:${port})`))
    }, timeout)
    let received = Buffer.alloc(0)
    conn.on('connect', () => {
      const len = Buffer.alloc(2)
      len.writeUInt16BE(queryBuf.length)
      conn.write(Buffer.concat([len, queryBuf]))
    })
    conn.on('data', (chunk) => {
      received = Buffer.concat([received, chunk])
      if (received.length >= 2) {
        const msgLen = received.readUInt16BE(0)
        if (received.length >= 2 + msgLen) {
          clearTimeout(timer)
          conn.destroy()
          resolve(received.slice(2, 2 + msgLen))
        }
      }
    })
    conn.on('error', (err) => {
      clearTimeout(timer)
      reject(err)
    })
  })
}

export async function dnsQuery(host, port, queryBuf, timeout = 5000) {
  const udpResult = await dnsQueryUDP(host, port, queryBuf, timeout)
  const tc = (udpResult.readUInt16BE(2) >> 9) & 1
  if (tc) return dnsQueryTCP(host, port, queryBuf, timeout)
  return udpResult
}

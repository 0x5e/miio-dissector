local p_miio = Proto("miio", "Xiaomi Mi Home Binary Protocol")
p_miio.prefs.token = Pref.string("Device token", "", "128-bit device token (in hex)")

local f_magic = ProtoField.uint16("miio.magic", "Magic", base.HEX)
local f_length = ProtoField.uint16("miio.length", "Length", base.DEC)
local f_unknown = ProtoField.uint32("miio.unknown", "Unknown", base.HEX)
local f_deviceId = ProtoField.uint32("miio.deviceId", "DeviceID", base.HEX)
local f_ts = ProtoField.uint32("miio.ts", "Timestamp", base.DEC)
local f_checksum = ProtoField.bytes("miio.checksum", "Checksum")
local f_encryptd_data = ProtoField.bytes("miio.encryptd_data", "Encrypted data")
local f_decrypted_data = ProtoField.string("miio.data", "Data")
p_miio.fields = { f_magic, f_length, f_unknown, f_deviceId, f_ts, f_checksum, f_encryptd_data, f_decrypted_data }

local function md5(str)
  local f = io.popen(string.format("echo '%s' | xxd -r -p - | openssl md5", str))
  local result = f:read("*a")
  result = string.gsub(result, "\n", "")
  f:close()
  return result
end

local function aes_128_cbc_decrypt(data, key, iv)
  local f = io.popen(string.format("echo '%s' | xxd -r -p - | openssl aes-128-cbc -d -K '%s' -iv '%s'", data:tohex(), key, iv))
  local result = f:read("*a")
  result = string.gsub(result, "\n", "")
  f:close()
  return result
end

local function miio_dissector(buf, pkt, root)
  if buf:len() < 32 then return false end

  local magic = buf(0, 2)
  if magic:uint() ~= 0x2131 then return false end

  local len = buf(2, 2)
  if buf:len() ~= len:uint() then return false end

  pkt.cols.protocol = "MIIO"

  local unknown = buf(4, 4)
  local deviceId = buf(8, 4)
  local ts = buf(12, 4)
  local checksum = buf(16, 16)

  local t = root:add(p_miio, buf)
  if len:uint() == 32 then
    if deviceId:uint() == 0xffffffff then
      pkt.cols.info = "Hello"
    else
      pkt.cols.info = "Hello Ack"
    end
  end

  t:add(f_magic, magic)
  t:add(f_length, len)
  t:add(f_unknown, unknown)
  t:add(f_deviceId, deviceId)
  t:add(f_ts, ts)
  t:add(f_checksum, checksum)

  if len:uint() > 32 then
    local data = buf(32, len:uint() - 32)
    local token = p_miio.prefs.token
    if (token ~= nil and token ~= "") then
      local key = md5(token)
      local iv = md5(string.format("%s%s", key, token))
      local decrypted_data = aes_128_cbc_decrypt(data:bytes(), key, iv)
      -- TODO trim && check valid
      pkt.cols.info = decrypted_data
      t:add(f_decrypted_data, data, decrypted_data)
    else
      t:add(f_encryptd_data, data)
    end
  end

  return true
end


local data_dis = Dissector.get("data")
function p_miio.dissector(buf, pkt, root)
  if miio_dissector(buf, pkt, root) then
    --valid MIIO diagram
  else
    data_dis:call(buf, pkt, root)
  end
end

local udp_encap_table = DissectorTable.get("udp.port")
udp_encap_table:add(54321, p_miio)

# Titik integrasi Roblox Lua (contoh pola, bukan patch otomatis)

Jangan mengubah seluruh importer. Ganti hanya pemeriksaan key lama dengan fungsi verifikasi server. URL harus diganti dengan URL Worker milikmu setelah deploy.

> Catatan: jika script berjalan di client/local environment, UserId yang dikirim oleh client dapat dipalsukan. Ini hanya gerbang akses dasar. Jangan menaruh rahasia admin atau OAuth secret di Lua.

```lua
local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")

local API_BASE = "https://GANTI-DENGAN-WORKER-URL"
local player = Players.LocalPlayer -- hanya tersedia dalam konteks client

local function verifyImporterKey(key)
    local ok, response = pcall(function()
        return HttpService:RequestAsync({
            Url = API_BASE .. "/api/verify",
            Method = "POST",
            Headers = { ["Content-Type"] = "application/json" },
            Body = HttpService:JSONEncode({
                key = key,
                robloxUserId = tostring(player.UserId)
            })
        })
    end)

    if not ok or not response.Success then
        return false, "Tidak dapat memverifikasi key."
    end

    local decodedOk, data = pcall(function()
        return HttpService:JSONDecode(response.Body)
    end)

    if not decodedOk then
        return false, "Respons backend tidak valid."
    end

    return data.valid == true, data.valid and "ACCESS GRANTED" or "INVALID ACCESS KEY"
end

-- Sambungkan hasil true ke fungsi impor asli yang sudah ada.
-- Jangan menjalankan importer sebelum hasil verifikasi true.
```

## Peringatan penting untuk Studio Lite
- `HttpService` harus diizinkan pada pengalaman Roblox jika script dijalankan di server game.
- Script importer yang berjalan di lingkungan Studio/editor mungkin tidak menyediakan `Players.LocalPlayer`, dan bisa jadi tidak dapat mengakses endpoint seperti game server.
- Jangan mengklaim ini sebagai pengamanan anti-bypass. Client yang dapat diedit pengguna dapat melewati pemeriksaan lokal.
- Sebelum membuat patch spesifik, cocokkan dengan fungsi autentikasi dan pemanggilan impor yang sebenarnya di source importer milikmu.

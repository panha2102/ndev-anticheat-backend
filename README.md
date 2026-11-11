# NPKP • Ndev Anti-Cheat Backend & Dashboard (`ndev-anticheat-backend`)

ប្រព័ន្ធ Backend API និងផ្ទាំងគ្រប់គ្រង Web Admin Dashboard សម្រាប់ **`code/components/ndev-core-five/`**។

---

## ១. ការដំឡើង និងដំណើរការ (Quick Start)

តម្រូវការ៖ **Node.js v22.5+ ឬ v24+** (ប្រើប្រាស់ Built-in `node:sqlite` ដោយមិនបាច់តម្លើង SQLite ឬ MySQL ក្រៅ)។

```powershell
cd ndev-anticheat-backend
Copy-Item .env.example .env
npm install
npm start
```

បន្ទាប់មកបើក Browser ចូលទៅកាន់៖
- **Dashboard UI:** [http://localhost:3005](http://localhost:3005)
- **Default Login:** `admin` / `changeme123` *(អាចផ្លាស់ប្ដូរបានភ្លាមក្នុងផ្ទាំង **ការកំណត់ & Discord**)*

---

## ២. API Endpoints ដែលភ្ជាប់ជាមួយ `ndev-core-five`

| Method | Endpoint | ប្រើប្រាស់ដោយ | ពិពណ៌នា |
|---|---|---|---|
| `GET` | `/api/anticheat/detections` | `ScreenshotCapture.cpp` | ផ្ដល់បញ្ជី `bannedProcesses` (`.exe` / `.dll`) ទៅឱ្យ Client |
| `POST` | `/submit` | `Scanner.cpp` | ទទួល Report (`BAN`, `WARNING`, `TRACKING`), រូបភាព Multi-Monitor Base64, Discord Webhook & Auto-Ban |
| `POST` | `/api/hwid/check-hwid` | `NdevAnticheat.cpp` | ឆែកស្ថានភាព HWID Ban រៀងរាល់ ១៥ វិនាទី |
| `POST` | `/api/anticheat/logs` | `NdevAnticheat.cpp` | ទទួល Log ពេលម៉ាស៊ីនដែលជាប់ Ban ត្រូវបានបង្ខំបិទហ្គេម (`0xAC01`) |
| `POST` | `/api/hwid/admin/ban-hwid-by-email` | Admin / External API | ដាក់ Ban គ្រប់ HWID ដែលធ្លាប់ Login ជាមួយ Email |
| `POST` | `/api/hwid/anticheat/ban` | Admin / External API | ដាក់ Ban HWID តាមរយៈ API (`X-Anticheat-Secret` ឬ Admin Session) |
| `POST` | `/api/hwid/admin/unban-hwid` | Admin / External API | ដោះ Ban HWID តាមរយៈ API |

---

## ៣. ការដាក់លើ Production Server (Nginx Reverse Proxy)

ទាំង `Component.cpp` (Scanner) និង `NdevAnticheat.cpp` (HWID Ban & Logs) ត្រូវបានភ្ជាប់មកកាន់ Domain តែមួយគត់គឺ **`https://anticheat.kampuchearp.com`** (មិនប៉ះពាល់ដល់ `https://apiv2.kampuchearp.com` ដែលប្រើសម្រាប់ Player Login ចូល Server ឡើយ)។

```nginx
# anticheat.kampuchearp.com (Scanner + HWID Ban + Logs + Admin Dashboard)
server {
    listen 80;
    server_name anticheat.kampuchearp.com;
    client_max_body_size 60M;

    location / {
        proxy_pass http://127.0.0.1:3005;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

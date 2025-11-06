# Simulasi-data-integrity-Logging-Monitoring_KWA-A

## Danendra Fidel Khansa (5027231063) KWA A

### Persiapan Penggunanaan Monitoring

1. Install dependensi

```
pip install -r requirements.txt
```

2. Jalankan monitor pertama kali (membuat baseline)

```
python monitor.py --dir ./secure_files
```

3. Jalankan sebagai service (polling tiap 5 detik)

```
python monitor.py --dir ./secure_files --watch --interval 5 --smtp-config smtp_config.json
```

4. Update Baseline

```
python3 monitor.py --auto-update
```

5. Jalankan web interface

```
python app.py
# lalu buka http://127.0.0.1:5000
```

### TEST CASE

1. Test Case untuk WARNING – File diubah (integrity failed)

- Pastikan kamu sudah punya baseline:

```
python monitor.py --dir ./secure_files
```

(Setelah itu, file hash_db.json akan terbuat.)

- Buka salah satu file di folder secure_files/, misalnya data.txt.

- Tambahkan atau ubah satu baris teks, contoh:

```
Hello world! File modified for test.
```

2. Test Case untuk ALERT – File baru muncul (unknown file)

- Tambahkan file baru ke folder secure_files/, misalnya:

```
echo "malicious content" > ./secure_files/hacked.txt
```

3. Test Case untuk ALERT – File dihapus (missing file)

- Hapus salah satu file lama, misalnya:

```
rm ./secure_files/data.txt
```

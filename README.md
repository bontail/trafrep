# trafrep

**trafrep** — инструмент для анализа и воспроизведения сетевого трафика PostgreSQL из pcap-файлов.

## Возможности
- Печать информации о запросах и соединениях из pcap-файла
- Воспроизведение трафика в реальном времени или с масштабированием скорости
- Сравнение двух pcap-файлов с визуализацией таймлайнов (HTML / SVG)
- Сбор benchmark-статистики PostgreSQL (`collect_info`)
- Фильтрация по хосту и порту

## Установка

```sh
git clone https://github.com/yourusername/trafRep.git
cd trafrep
go build
```

## Использование

### Получение трафика для воспроизведения

##### Вместе с psql
1. Запустить tcpdump (lo0 - macOS, lo - linux)
```shell
sudo tcpdump -s 0 -w someName.pcap -i lo0 port 5432
```
2. Подключиться (обязательно после включения tcpdump) к PostgreSQL с помощью psql и выполнить несколько запросов
3. (Желательно) Остановить psql
4. Остановить tcpdump

##### Вместе с языком программирования

1. Запустить tcpdump (lo0 - macOS, lo - linux)
```shell
sudo tcpdump -s 0 -w someName.pcap -i lo0 port 5432
```
2. Запустить код, который будет делать запросы к PostgreSQL
<details>
<summary>Python (в качестве примера)</summary>

```python
import psycopg2

DB_CONFIG = {
    'host': 'localhost',
    'database': 'postgres',
    'user': 'postgres',
    'password': 'postgres',
    'port': 5432,
    'sslmode': 'disable',
}


def main():
    conn1 = psycopg2.connect(**DB_CONFIG)
    print("Успешно подключились к PostgreSQL")
    with conn1.cursor() as cur1:
        insert_query = """
            INSERT INTO some_table (value)
                VALUES (1)               
        """
        cur1.execute(insert_query)
        conn1.commit()
    print("Запрос отработал")


if __name__ == '__main__':
    main()
```
</details>

3. Остановить tcpdump

#### Печать информации
```sh
go run main.go print --pcap someName.pcap
```

Доступные флаги:


| Флаг | По умолчанию | Описание |
|------|-------------|----------|
| `--pcap` | — | Путь к pcap файлу (**обязательный**) |
| `--host` | — | IP-адрес PostgreSQL сервера для фильтрации |
| `--port` | `5432` | Порт PostgreSQL для фильтрации |
| `--filter` | `both` | Сторона вывода: `clients` / `server` / `both` |

### Воспроизведение трафика
```sh
go run main.go replay --pcap someName.pcap --print-query
```

Доступные флаги:


| Флаг | По умолчанию | Описание |
|------|-------------|----------|
| `--pcap` | — | Путь к pcap файлу (**обязательный**) |
| `--target-host` | `127.0.0.1` | Хост целевого PostgreSQL |
| `--target-port` | `5432` | Порт целевого PostgreSQL |
| `--rate` | `1.0` | Множитель скорости воспроизведения |
| `--print-query` | `false` | Печатать текст запроса при отправке |
| `--ready-timeout` | `25` | Таймаут ожидания ответа сервера (секунды) |
| `--host` | — | IP-адрес PostgreSQL сервера для фильтрации |
| `--port` | `5432` | Порт PostgreSQL для фильтрации |

### Сравнение двух pcap-файлов

Команда `compare` читает два pcap-файла, строит таймлайны запросов по каждому стриму и генерирует визуализацию в формате HTML или SVG.

```sh
go run main.go compare --pcap1 original.pcap --pcap2 repeat.pcap --output result.html
```

Пример с дополнительными параметрами:
```sh
go run main.go compare \
  --pcap1 original.pcap \
  --pcap2 replay.pcap \
  --format html \
  --output compare.html \
  --delta-show 1ms \
  --delta-color 10ms
```

Доступные флаги:


| Флаг | По умолчанию | Описание |
|------|-------------|----------|
| `--pcap1` | — | Путь к первому pcap файлу (**обязательный**) |
| `--pcap2` | — | Путь ко второму pcap файлу (**обязательный**) |
| `--format` | `html` | Формат вывода: `html` |
| `--output` | `compare.html` | Путь к выходному файлу |
| `--delta-show` | `1ms` | Порог отображения дельты рядом с сообщением |
| `--delta-color` | `10ms` | Порог смены цвета сообщения при превышении дельты |
| `--host` | — | IP-адрес PostgreSQL сервера для фильтрации |
| `--port` | `5432` | Порт PostgreSQL для фильтрации |

### Сбор benchmark-статистики PostgreSQL

```sh
go run main.go collect_info --host 127.0.0.1 --user postgres --password postgres --label original --out results
```

Доступные флаги:

| Флаг | По умолчанию | Описание |
|------|-------------|----------|
| `--host` | `127.0.0.1` | Хост PostgreSQL |
| `--port` | `5432` | Порт PostgreSQL |
| `--dbname` | `postgres` | База данных |
| `--user` | `postgres` | Пользователь |
| `--password` | `postgres` | Пароль |
| `--label` | `run` | Метка snapshot-файла |
| `--out` | `.` | Каталог для JSON-результата |

### Сравнение benchmark-статистики (`collect_info` snapshots)

```sh
go run main.go compare_stats results/original_*.json results/replay_*.json --out results/report.html
```

Доступные флаги:

| Флаг | По умолчанию | Описание |
|------|-------------|----------|
| `--out` | `pg_compare.html` | Путь к HTML-отчету |
| `--output` | `pg_compare.html` | Алиас для `--out` |


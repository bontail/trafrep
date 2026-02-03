# trafrep

**trafrep** — инструмент для анализа и воспроизведения сетевого трафика PostgreSQL из pcap-файлов.

## Возможности
- Печать информации о запросах и соединениях из pcap-файла
- Воспроизведение трафика в реальном времени или с масштабированием скорости
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
1. Запустить tcdump (lo0 - macOS, l0 - linux)
```shell
sudo tcpdump -s 0 -w someName.pcap -i lo0 port 5432
```
2. Подключиться (обязательно после включения tcpdump) к PostgreSQL с помощью psql и выполнить несколько запросов
3. (Желательно) Остановить psql
4. Остановить tcdump

##### Вместе с языком программирования

1. Запустить tcdump (lo0 - macOS, l0 - linux)
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

3. Остановить tcdump

#### Печать информации
```sh
./trafRep print
```

### Воспроизведение трафика
```sh
./trafRep replay --pcap filename.pcap --print-query
```


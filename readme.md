# IEC-104. Клиент - серверное приложение

## БДЗ по курсу "Информационная безопасность АСУ ТП"

## Выполнили студенты 4го курса НИЯУ "МИФИ", группы Б17-505:

1. Зоричев Виталий
2. Рудик Максим
3. Савченко Антон
4. Худоярова Анастасия

## Описание

За основу был взят симулятор IEC-104 трафика https://github.com/RocyLuo/IEC104TCP. Однако он не является полностью рабочим, поскольку написан для Python2, а также содержит ошибку в коде.<br/>

Поэтому данная реализация была модифицирована:

1. интерпретирована под Python3,
2. устранена ошибка (в библиотеке scapy, файл `fields.py` на локальном компьютере необходимо заменить 167-ю строку на `return copy.copy(x)`, ошибка именно в стандартной библиотеке)
3. выполнено корректное завершние соединения между клиентом и сервером
4. исправлены названия файлов, чтобы они соответствовали своей реальной функциональности (то есть сервер в изначальном симуляторе на самом деле должен быть клиентом, а клиент сервером).

## Запуск

Перед запуском проверьте наличие библиотеки scapy. (Для ее установки: `python3 -m pip install scapy`). И запустите пример.

```python
python3 EchoIEC104Client.py
python3 example.py
```

Данные для теста описаны в `iec104_tcp_packets.py` и представляют собой APDU (APCI и ASDU).

## Формирование трафика

После запуска `example.py` формируется передача данных по IEC-104. <br/>

### Содержание дампа.

При запуске формируются блоки данных на прикладном уровне (ASDU) с идентификаторами типа 45,46,47,48,58,59,60,61,62,50,101,103, и управляющая информация прикладного уровня(APCI: с форматами поля управления "s", "i","u")

> 45(C_SC_NA_1) - однопозиционная команда <br/>
> 46(C_DC_NA_1) - двухпозиционная команда <br/>
> 47(C_RC_NA_1) - команда пошагового регулирования<br/>
> 48(C_SE_NA_1) - команда уставки, нормализованное значение<br/>
> 50(C_SE_NC_1) - команда уставки, короткий формат плавающей запятой<br/>
> 58(C_SC_TA_1) - однопозиционная команда с меткой времени СР56Время2а<br/>
> 59(C_DC_TA_1) - двухпозиционная команда с меткой времени СР56Время2а<br/>
> 60(C_RC_TA_1) - командапошагового регулирования с меткой времени СР56Время2а<br/>
> 61(C_SE_TA_1) - командауставки, нормализованное значение с меткой времени СР56Время2а<br/>
> 62(C_SE_TB_1) - командауставки,масштабированное значение с меткой времени СР56Время2а<br/>
> 101(C_CI_NA_1) - команда опроса счетчиков<br/>
> 103(C_CS_NA_1) - команда синхронизации часов<br/>

Результирующий дамп находится в `result.pcanpg`.

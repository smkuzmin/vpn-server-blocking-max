## Блокировка MAX, VK, OK, Mail.Ru на VPN-сервере

### Зачем это нужно

Мессенджер **MAX** [отслеживает](https://habr.com/ru/articles/1006666/) пользователей, подключённых через **VPN**, и может передавать реальный **IP**-адрес сервера в **РКН**.
Чтобы исключить риск раскрытия своей инфраструктуры, мы блокируем весь исходящий **Web**-трафик (порты **80**/**443**) от **VPN**-клиентов к доменам следующих сервисов:

- **Мессенджер MAX**
- **ВКонтакте**
- **Одноклассники**
- **Mail.ru Group**


### Клиентская часть

- **Приложение**: [Amnezia VPN](https://play.google.com/store/apps/details?id=org.amnezia.vpn) для Android
- **Развёртывание**: автоматическое, через приложение (инструкция в [видео](https://www.youtube.com/watch?v=ckIFYUkqDnc))


### Серверная часть

- **Хостинг**: Бюджетный VPS в ЕС: [HostVDS](https://hostvds.com/?affiliate_uuid=45e30dfa-ebf0-4f0c-aca2-3f3cfd07f84f), [VDSina](https://vdsina.com/ru) (Финляндия, Латвия, Германия, Нидерланды)
- **ОС**: Ubuntu 22.04 LTS
- **VPN**: AmneziaWG (WireGuard) в Docker-контейнере
- **Сетевой интерфейс**: `amn0` (AmneziaWG)
- **Цепочка фильтрации**: `DOCKER-USER` (обрабатывает весь forwarded-трафик от клиентов)

Важно: Весь трафик от VPN-клиентов проходит через цепочку **DOCKER-USER** в **iptables** - именно здесь мы добавляем правила блокировки.

| Файл                         | Назначение                                                                                        |
| ---------------------------- | ------------------------------------------------------------------------------------------------- |
| /root/**max-block**          | Основной скрипт - резолвинг доменов в IP, агрегация подсетей, применение правил **iptables**      |
| /root/**max-block-clear**    | Очистка всех правил в цепочке **DOCKER-USER** и очистка лога                                      |
| /root/**max-block-cron-on**  | Включение автозапуска скрипта **max-block** в **cron** (каждые 5 минут)                           |
| /root/**max-block-cron-off** | Отключение автозапуска скрипта **max-block** в **cron**                                           |
| /root/**max-block-status**   | Отображение количества активных правил блокировки и их содержимого с подсветкой                   |
| /root/**max-block-log**      | Просмотр лога выполнения скрипта **max-block**                                                    |
| /root/**ipaggr**             | Perl-скрипт агрегации IP-адресов и сетей (с сортировкой и объединением комментариев)              |
| /root/**max-block.domains**  | Список доменов для блокировки (один домен на строку, # — комментарий). Редактируется вручную      |
| /root/**max-block.ips**      | Автоматически генерируемый список IP-адресов и подсетей с комментариями. Не редактировать вручную |
| /var/log/**max-block.log**   | Лог-файл выполнения скрипта **max-block** с временными метками и результатами применения правил   |
| /var/lock/**max-block.lock** | Файл блокировки, предотвращающий параллельный запуск скрипта **max-block**                        |

Что делает основной скрипт **max-block**:

 - Читает домены из списка **max-block.domains**, разрешает их в IP-адреса и дописывает к списку IP-адресов и сетей **max-block.ips**.
 - Читает **max-block.ips**, суммаризует их скриптом **ipaggr**, и записыват обратно.
 - Читает **max-block.ips** и для каждого IP-адреса или сети создает правило блокировки (перед добавлением правила проверяет, есть ли уже такое).

***

#### Содержимое скриптов и файлов конфигурации

##### ipaggr
```perl
#!/usr/bin/perl

use strict;
use warnings;
use Socket;

# === Показ справки ===
sub show_help {
    print <<'HELP';

IPAggr v1.1 - IPv4 Aggregator

Merges overlapping and adjacent IPv4 addresses and subnets into the minimum number
of networks, preserving and merging comments from the original list.

FEATURES:
  - Skips invalid lines without errors (empty lines, comments, text)
  - Automatically processes single IP addresses as /32
  - Outputs single addresses without /32 prefix
  - Automatic ascending sorting
  - Supports both CIDR prefixes and subnet masks (e.g., 192.168.1.0/24 or 192.168.1.0/255.255.255.0)
  - Preserves and merges comments from input lines
  - Fixed-width output format: "%-18s # %s"
  - Comments sorted alphabetically (case-insensitive)

INPUT FORMAT:
  192.168.0.0/24             # Network with CIDR prefix
  192.168.1.0/255.255.255.0  # Network with subnet mask
  192.168.1.1                # Single IP address
  192.168.2.1                # Single IP address

OUTPUT FORMAT:
  192.168.0.0/23     # comment1, comment2, ...
  192.168.2.1        # comment

USAGE:
  cat file.lst | ipaggr
  ipaggr < file.lst
  ipaggr < file.lst > output.lst

HELP
    exit 0;
}

# Проверка аргументов и stdin
show_help() if @ARGV && ($ARGV[0] eq '-h' || $ARGV[0] eq '--help');
show_help() if -t STDIN && !@ARGV;

my %nets;       # Хранит сети: $nets{"192.168.0.0/24"} = 1
my %comments;   # Хранит комментарии: $comments{"192.168.0.0/24"} = "comment"

while (<>) {
    chomp;
    s/\r//g;
    s/^\s+//;

    my ($token) = split(/[\s#]+/, $_);
    next unless defined $token && $token ne '';

    my $comment = '';
    if (/#(.*)$/) {
        $comment = $1;
        $comment =~ s/^\s+|\s+$//g;
    }

    my ($ip, $mask) = split('/', $token);
    $mask ||= 32;

    next if $mask !~ /^\d+$/;
    next if $mask < 0 || $mask > 32;

    my $num = unpack("N", inet_aton($ip));
    next unless defined $num;

    my $net = $num & (0xFFFFFFFF << (32 - $mask));
    my $cidr = "$net/$mask";

    $nets{$cidr} = 1;
    if ($comment ne '') {
        $comments{$cidr} = merge_comments($comments{$cidr}, $comment);
    }
}

# === Этап 1: Поглощение подсетей ===
my $changed = 1;
while ($changed) {
    $changed = 0;
    my @to_remove;

    for my $cidr_small (keys %nets) {
        next if $nets{$cidr_small} == 0;
        my ($net_small, $mask_small) = split('/', $cidr_small);

        for my $cidr_large (keys %nets) {
            next if $cidr_small eq $cidr_large;
            next if $nets{$cidr_large} == 0;
            my ($net_large, $mask_large) = split('/', $cidr_large);

            next if $mask_small <= $mask_large;

            my $prefix_large = 32 - $mask_large;
            my $net_large_start = $net_large & (0xFFFFFFFF << $prefix_large);
            my $net_large_end = $net_large_start + (1 << $prefix_large) - 1;

            my $prefix_small = 32 - $mask_small;
            my $net_small_start = $net_small & (0xFFFFFFFF << $prefix_small);
            my $net_small_end = $net_small_start + (1 << $prefix_small) - 1;

            if ($net_large_start <= $net_small_start && $net_small_end <= $net_large_end) {
                if (!$comments{$cidr_large} || $comments{$cidr_large} eq '') {
                    $comments{$cidr_large} = $comments{$cidr_small};
                }
                push @to_remove, $cidr_small;
                $nets{$cidr_small} = 0;
                $changed = 1;
                last;
            }
        }
    }
    delete @nets{@to_remove};
}

# === Этап 2: Агрегация соседних блоков ===
$changed = 1;
while ($changed) {
    $changed = 0;
    my %new_nets;
    my %new_comments;

    for my $cidr (keys %nets) {
        next if $nets{$cidr} == 0;

        my ($net, $mask) = split('/', $cidr);
        next if $mask == 0;

        my $brother = ($net ^ (1 << (32 - $mask))) . "/$mask";

        if (exists $nets{$brother} && $nets{$brother} == 1) {
            my $parent_mask = $mask - 1;
            my $parent_net = $net & (0xFFFFFFFF << (32 - $parent_mask));
            my $parent_cidr = "$parent_net/$parent_mask";

            $new_nets{$parent_cidr} = 1;
            $new_comments{$parent_cidr} = merge_comments(
                $comments{$cidr},
                $comments{$brother}
            );

            $nets{$cidr} = 0;
            $nets{$brother} = 0;
            $changed = 1;
        } else {
            $new_nets{$cidr} = 1;
            $new_comments{$cidr} = $comments{$cidr};
        }
    }
    %nets = %new_nets;
    %comments = %new_comments;
}

# Вывод результата
for my $cidr (sort {
    my ($a_net, $a_mask) = split('/', $a);
    my ($b_net, $b_mask) = split('/', $b);
    $a_net <=> $b_net || $a_mask <=> $b_mask;
} keys %nets) {
    my ($net, $mask) = split('/', $cidr);

    my $ip_str = inet_ntoa(pack("N", $net));
    $ip_str .= "/$mask" if $mask != 32;

    if ($comments{$cidr}) {
        printf "%-18s # %s\n", $ip_str, $comments{$cidr};
    } else {
        print "$ip_str\n";
    }
}

# === Функция объединения комментариев ===
# Всегда сортирует комментарии алфавитно (без учёта регистра)
sub merge_comments {
    my ($c1, $c2) = @_;

    # Собираем все комментарии в хеш для удаления дубликатов
    my %seen;

    # Обрабатываем первый комментарий (если есть)
    if ($c1 && $c1 ne '') {
        my @parts = split(/,\s*|\s+/, $c1);
        $seen{$_} = 1 for grep { $_ } @parts;
    }

    # Обрабатываем второй комментарий (если есть)
    if ($c2 && $c2 ne '') {
        my @parts = split(/,\s*|\s+/, $c2);
        $seen{$_} = 1 for grep { $_ } @parts;
    }

    # Возвращаем пустую строку, если комментариев нет
    return '' unless %seen;

    # Сортируем алфавитно (без учёта регистра) и объединяем
    my @sorted = sort { lc($a) cmp lc($b) } keys %seen;
    return join(', ', @sorted);
}
```

##### max-block
```bash
#!/bin/bash

# Интерфейс WireGuard
WG_IF="amn0"

# Список блокируемых доменов
DOMAINS="/root/max-block.domains"

# Список блокируемых IP и сетей
IPS="/root/max-block.ips"

# Лог-файл
LOG="/var/log/max-block.log"

# Лок-файл
LOCK="/var/lock/max-block.lock"

# Защита от параллельного запуска скрипта
mkdir 2>/dev/null -p "`dirname "$LOCK"`"
exec 200>"$LOCK"
flock -n 200 || { echo "ERROR: Script is already running. Please wait for it to complete."; exit 1; }

# Читаем список доменов, разрешаем их в IP и добавляем в список блокируемых IP и сетей
cat 2>/dev/null "$DOMAINS"|grep -Ev '(^#|^[ \t]*$)'|awk '{print $1}'|sort -u \
|while read domain other; do
   getent 2>/dev/null ahostsv4 "$domain"|grep STREAM|awk '{print $1}'|sort -u \
   |while read ip other; do
      printf>>"$IPS" "%-18s # %s\n" "$ip" "$domain"
    done
 done

# Агрегируем IP и сети
cat 2>/dev/null "$IPS"|grep -Ev '(^#|^[ \t]*$)'|/root/ipaggr>"$IPS.tmp"
mv -f "$IPS.tmp" "$IPS"

# Читаем список IP/сетей и блокируем для каждой исходящий трафик от VPN-клиентов на WEB-портах
cat 2>/dev/null "$IPS"|grep -Ev '(^#|^[ \t]*$)' \
|while read ip delimiter name other; do
   # Берем только первое имя (без запятой)
   name=${name/%,*/}
   iptables -C DOCKER-USER -i "$WG_IF" -d "$ip" -p tcp -m multiport --dports 80,443 -j DROP -m comment --comment "max-block: $name" &>/dev/null || \
 ( iptables -I DOCKER-USER -i "$WG_IF" -d "$ip" -p tcp -m multiport --dports 80,443 -j DROP -m comment --comment "max-block: $name"
   printf "%s  %-18s # %s\n" "`date '+%Y-%m-%d %H:%M'`" "$ip" "$name" )
 done \
 |tee -a -i "$LOG"
```

##### max-block-clear
```bash
#!/bin/bash

# Очистка всех правил в цепочке
iptables -F DOCKER-USER

# Очистка лога
echo>/var/log/max-block.log ""

# Показ статуса
/root/max-block-status
```

##### max-block-cron-off
```bash
#!/bin/bash

# Удаляем задание
crontab 2>/dev/null -l|grep -v max-block|crontab -

# Проверяем что задание существует
crontab 2>/dev/null -l|grep --color max-block
```

##### max-block-cron-on
```bash
#!/bin/bash

# Выходим, если задание уже существует
crontab 2>/dev/null -l|grep --color max-block && exit

# Добавляем задание в cron
(crontab 2>/dev/null -l; echo "*/5 * * * * /root/max-block")|crontab -

# Проверяем что задание существует
crontab 2>/dev/null -l|grep --color max-block
```

##### max-block-log
```bash
#!/bin/bash

# Выводим лог
cat /var/log/max-block.log
```

##### max-block-status
```bash
#!/bin/bash

# Показываем количество правил
echo
echo Rules count: `iptables -L DOCKER-USER -v -n|grep max-block|wc -l`
echo

# Показываем правила
iptables -L DOCKER-USER -v -n|grep --color '\/\* max-block: .*'
```

##### max-block.domains
```powershell
# MAX domains
api.oneme.ru                # Основной API: чаты, авторизация, синхронизация
fd.oneme.ru                 # Файловый сервис: загрузка/скачивание медиа
i.oneme.ru                  # Изображения: аватарки, превью, стикеры
sdk-api.apptracer.ru        # AppTracer: crash-отчёты, производительность
max.ru                      # Корневой домен бренда
mycdn.me                    # Основной CDN VK: картинки, видео, файлы
okcdn.ru                    # CDN Одноклассников: медиа-контент
pimg.mycdn.me               # Медиа-аналитика: превью, статистика просмотров
st.max.ru                   # Статика веб-интерфейса: CSS, JS, шрифты
tracker-api.vk-analytics.ru # VK Analytics: события, метрики, телеметрия
web.max.ru                  # Веб-версия мессенджера
ws-api.oneme.ru             # WebSocket: real-time сообщения, статусы онлайн

# IP Check
api.ipify.org               # Сервис определения внешнего IP
checkip.amazonaws.com       # AWS: сервис проверки внешнего IP-адреса
ifconfig.me                 # Публичный сервис определения IP
ip.mail.ru                  # Mail.ru: сервис определения внешнего IP
ipv4-internet.yandex.net    # Яндекс: проверка IPv4-доступа
ipv6-internet.yandex.net    # Яндекс: проверка IPv6-доступа

# VPN Detect
calls.okcdn.ru              # OK: инфраструктура голосовых/видеозвонков
gosuslugi.ru                # Госуслуги: может использоваться для верификации
#gstatic.com                # Google CDN: шрифты, библиотеки (закомментировано)
main.telegram.org           # Telegram: основной домен для детекта мессенджера
mmg.whatsapp.net            # WhatsApp: инфраструктура мета-сервисов
mtalk.google.com            # Google Cloud Messaging: push-уведомления

# OK (Odnoklassniki)
ads.ok.ru                   # OK: рекламная платформа
api.odnoklassniki.ru        # OK: устаревший API-шлюз (legacy)
api.ok.ru                   # OK: основной API для мобильных приложений
audio.ok.ru                 # OK: аудиостриминг, музыка
cdn.ok.ru                   # OK: CDN для статического контента
connect.odnoklassniki.ru    # OK: сервис авторизации и социал-логина
odnoklassniki.ru            # OK: основной домен сайта (редирект на ok.ru)
odnoklassniki-cdn.ru        # OK: дополнительный CDN-домен
connect.ok.ru               # OK: OAuth и социальная авторизация
i.ok.ru                     # OK: изображения, аватарки, медиа
m.ok.ru                     # OK: мобильная версия сайта
metrics.ok.ru               # OK: сбор метрик и аналитики
mobile.ok.ru                # OK: мобильный API/интерфейс
notify.vk.com               # VK: сервис уведомлений (общий с ОК)
ok.ru                       # OK: главный домен социальной сети
okcdn.ru                    # OK: CDN для медиаконтента
okmedia.ru                  # OK: медиасервисы, видео, стриминг
okstatic.com                # OK: статические ресурсы (стили, скрипты)
payment.ok.ru               # OK: платёжный шлюз, покупка ОК-валюты
static.ok.ru                # OK: хостинг статики сайта
video.ok.ru                 # OK: видеоплатформа, стриминг
widget.ok.ru                # OK: виджеты для встраивания на сторонние сайты
www.ok.ru                   # OK: www-поддомен основного сайта

# VK (VKontakte)
ads.vk.com                  # VK: рекламная платформа MyTarget
api.vk.com                  # VK: основной API для разработчиков и приложений
app.vk.com                  # VK: платформа мини-приложений
connect.vk.com              # VK: OAuth, социальная авторизация
count.vk.com                # VK: счётчики, статистика, аналитика
dev.vk.com                  # VK: портал для разработчиков
donate.vk.com               # VK: сервис донатов, поддержка авторов
firebase.vk.com             # VK: Firebase-интеграция для push-уведомлений
games.vk.com                # VK: игровая платформа, браузерные игры
id.vk.com                   # VK: управление аккаунтом, профиль
login.vk.com                # VK: страница авторизации, вход в аккаунт
m.vk.com                    # VK: мобильная версия сайта
mail.vk.com                 # VK: почтовый сервис
mobile.vk.com               # VK: мобильный API/интерфейс
music.vk.com                # VK: музыкальный стриминг, плейлисты
mycdn.me                    # VK: общий CDN для медиа (дублируется в MAX)
new.vk.com                  # VK: тестовый/бета-интерфейс
notify.vk.com               # VK: сервис пуш-уведомлений
oauth.vk.com                # VK: OAuth 2.0 endpoint для авторизации
persiq.vk.com               # VK: персонализированные рекомендации, ИИ
platform.vk.com             # VK: платформа для виджетов и интеграций
pp.userapi.com              # VK: пользовательские фото (profile pictures)
push.vk.com                 # VK: инфраструктура push-уведомлений
st.vk.com                   # VK: статика сайта (стили, скрипты, иконки)
st2.vk.com                  # VK: дополнительный сервер статики
st3.vk.com                  # VK: дополнительный сервер статики
st4.vk.com                  # VK: дополнительный сервер статики
stat.vk.com                 # VK: сбор статистики, аналитика
static.vk.com               # VK: хостинг статических файлов
sun1.userapi.com            # VK: пользовательский контент (фото, видео)
sun2.userapi.com            # VK: пользовательский контент (фото, видео)
tracker.vk.com              # VK: трекер событий, аналитика поведения
userapi.com                 # VK: API для пользовательского контента
video.vk.com                # VK: видеоплатформа, клипы, трансляции
vk-analytics.ru             # VK: платформа аналитики для разработчиков
vk-apps.com                 # VK: каталог и хостинг приложений
vk-apps.ru                  # VK: каталог приложений (зеркало)
vk-play.ru                  # VK: игровая платформа, облачный гейминг
vk.cc                       # VK: сервис сокращения ссылок
vk-cdn.net                  # VK: основной CDN для медиаконтента
vk-cdn.me                   # VK: дополнительный CDN-домен
vk-portal.net               # VK: портал для партнёров и интеграций
vk.com                      # VK: главный домен социальной сети
vk.company                  # VK: корпоративный сайт, информация о компании
vk.link                     # VK: сервис коротких ссылок
vk.me                       # VK: персональные ссылки на профиль
vk.page                     # VK: сервис создания лендингов/страниц
vk.ru                       # VK: русскоязычное зеркало основного домена
vkmusic.ru                  # VK: отдельный домен музыкального сервиса
vkplay.ru                   # VK: игровая платформа (зеркало)
vkportal.net                # VK: партнёрский портал (зеркало)
vkteam.ru                   # VK: сайт для разработчиков и команды
vkuser.net                  # VK: хостинг пользовательского контента
vkuseraudio.net             # VK: стриминг пользовательского аудио
vkuserphoto.net             # VK: хостинг пользовательских фотографий
vkuservideo.net             # VK: стриминг пользовательского видео
vkvideo.com                 # VK: видеоплатформа (международный домен)
vkvideo.ru                  # VK: видеоплатформа (российский домен)
www.vk.com                  # VK: www-поддомен основного сайта

# MAIL.RU GROUP
beget.com                   # Beget: хостинг-провайдер (инфраструктура Mail.ru)
beget.ru                    # Beget: хостинг-провайдер (российский домен)
icq.com                     # ICQ: мессенджер (принадлежит VK/Mail.ru)
icq.net                     # ICQ: дополнительный домен мессенджера
imgsmail.ru                 # Mail.ru: хостинг изображений, аватарок
mail.ru                     # Mail.ru: главный портал, почта, сервисы
top.mail.ru                 # Mail.ru: рейтинг сайтов, аналитика

# ANALYTICS AND TRACKERS
count.vk.com                # VK: счётчики посещаемости, аналитика
counter.yadro.ru            # Яндекс.Метрика: сбор статистики посещений
metrics.ok.ru               # OK: сбор метрик производительности и событий
stat.vk.com                 # VK: статистика, аналитика поведения
top.mail.ru                 # Mail.ru: рейтинг, аналитика трафика
tracker.vk.com              # VK: трекер пользовательских событий
vk-analytics.ru             # VK: платформа аналитики для приложений
```

##### max-block.ips
```powershell
3.85.158.60        # checkip.amazonaws.com
3.215.252.116      # checkip.amazonaws.com
3.223.26.135       # checkip.amazonaws.com
5.45.196.64        # ipv4-internet.yandex.net
5.61.16.0/21       # ODNOKLASSNIKI-FRONT
5.61.232.0/21      # VK-FRONT
5.101.40.0/22      # ODNOKLASSNIKI-FRONT
5.181.60.0/22      # VK-FRONT
5.188.140.0/22     # VKCS
13.218.10.232      # checkip.amazonaws.com
31.13.72.52        # mmg.whatsapp.net
31.13.73.52        # mmg.whatsapp.net
31.177.104.0/22    # RU-DTP-20110314
34.0.201.80        # okstatic.com
34.160.111.145     # ifconfig.me
34.231.230.75      # checkip.amazonaws.com
34.251.25.101      # checkip.amazonaws.com
34.251.143.91      # checkip.amazonaws.com
34.253.23.170      # checkip.amazonaws.com
34.254.77.2        # checkip.amazonaws.com
37.139.32.0/22     # VKCS
37.139.40.0/22     # VKCS
37.187.83.72       # okmedia.ru
44.196.45.43       # checkip.amazonaws.com
44.218.27.178      # checkip.amazonaws.com
45.84.128.0/22     # VK-FRONT
45.136.20.0/22     # ODNOKLASSNIKI-FRONT
46.51.192.183      # checkip.amazonaws.com
52.7.205.187       # checkip.amazonaws.com
52.48.247.5        # checkip.amazonaws.com
52.72.44.208       # checkip.amazonaws.com
52.205.193.90      # checkip.amazonaws.com
52.208.199.116     # checkip.amazonaws.com
54.225.183.3       # checkip.amazonaws.com
54.228.15.104      # checkip.amazonaws.com
62.217.160.0/20    # VK-FRONT
64.190.63.222      # vkvideo.com
64.233.161.188     # mtalk.google.com
64.233.162.188     # mtalk.google.com
64.233.163.188     # mtalk.google.com
64.233.164.188     # mtalk.google.com
64.233.165.188     # mtalk.google.com
65.21.178.24       # vk-cdn.me
74.125.131.188     # mtalk.google.com
74.125.205.188     # mtalk.google.com
79.137.157.0/24    # M100-COLO
79.137.174.0/23    # VKCS
79.137.240.0/21    # VK-FRONT
83.166.232.0/21    # VKCS
83.166.248.0/21    # VKCS
83.217.216.0/22    # VKCS
83.222.28.0/22     # RU-ODNOKLASSNIKI-20040421
84.23.52.0/22      # VKCS
85.192.32.0/22     # VKCS
87.239.104.0/21    # VKCS
87.240.129.133     # app.vk.com
87.240.129.140     # api.vk.com
87.240.129.187     # dev.vk.com
87.240.129.191     # vk-portal.net
87.240.132.64      # dev.vk.com
87.240.132.67      # app.vk.com
87.240.132.72      # app.vk.com
87.240.132.78      # app.vk.com
87.240.137.130     # api.vk.com
87.240.137.137     # pp.userapi.com
87.240.137.164     # app.vk.com
87.240.137.206/31  # api.vk.com
87.240.137.208     # api.vk.com
87.240.139.193     # api.vk.com
87.240.190.64      # mail.vk.com
87.240.190.70      # api.vk.com
87.240.190.75      # api.vk.com
87.240.190.77      # pp.userapi.com
87.242.112.0/22    # RU-ODNOKLASSNIKI-20050722
88.212.201.198     # counter.yadro.ru
88.212.201.204     # counter.yadro.ru
88.212.202.52      # counter.yadro.ru
89.208.84.0/22     # VKCS
89.208.196.0/22    # VKCS
89.208.208.0/22    # VKCS
89.208.216.0/21    # VKCS
89.208.228.0/22    # VKCS
89.221.228.0/22    # RU-NETBRIDGE-20061011
89.221.232.0/21    # RU-NETBRIDGE-20061011
90.156.148.0/22    # VKCS
90.156.212.0/22    # VKCS
90.156.216.0/22    # VKCS
90.156.232.0/21    # RU-NETBRIDGE-20061117
91.219.224.0/22    # KZ-VKTECH-20101026
91.231.132.0/22    # RU-NETBRIDGE
92.38.217.0/24     # BLINK-NET
93.186.225.194     # app.vk.com
93.186.225.200     # pp.userapi.com
93.186.225.205     # api.vk.com
93.186.237.1       # connect.vk.com
93.186.237.6/31    # persiq.vk.com
93.186.237.16      # persiq.vk.com
94.100.176.0/20    # VK-FRONT
94.139.244.0/22    # VKCS
95.142.194.165     # notify.vk.com
95.142.204.191     # sun1.userapi.com
95.163.32.0/19     # VK-FRONT
95.163.133.0/24    # DINET
95.163.180.0/22    # VKCS
95.163.208.0/21    # VKCS
95.163.216.0/22    # VK-FRONT
95.163.248.0/21    # VKCS
95.213.27.254      # vk-apps.com
95.213.37.126      # vkuser.net
95.213.56.1        # connect.vk.com
95.213.56.2/31     # persiq.vk.com
95.213.56.4        # persiq.vk.com
98.94.198.74       # checkip.amazonaws.com
100.27.88.178      # checkip.amazonaws.com
100.31.30.154      # checkip.amazonaws.com
100.51.38.154      # checkip.amazonaws.com
104.26.12.205      # api.ipify.org
104.26.13.205      # api.ipify.org
107.20.202.9       # checkip.amazonaws.com
108.177.14.188     # mtalk.google.com
109.120.180.0/22   # VKCS
109.120.188.0/22   # VKCS
128.140.168.0/21   # VK-FRONT
130.49.224.0/19    # RU-NETBRIDGE-19880518
142.250.150.188    # mtalk.google.com
142.251.1.188      # mtalk.google.com
146.185.208.0/22   # VKCS
146.185.240.0/22   # VKCS
149.154.167.99     # main.telegram.org
155.212.192.0/20   # RU-NETBRIDGE-19911202
157.240.205.60     # mmg.whatsapp.net
172.67.74.152      # api.ipify.org
172.253.130.188    # mtalk.google.com
172.253.152.188    # mtalk.google.com
173.194.73.188     # mtalk.google.com
173.194.220.188    # mtalk.google.com
173.194.221.188    # mtalk.google.com
173.194.222.188    # mtalk.google.com
176.31.179.191     # okmedia.ru
176.112.168.0/21   # VK-FRONT
178.22.88.0/21     # RU-NETBRIDGE-20100406
178.237.16.0/20    # VK-FRONT
185.5.136.0/22     # VK-FRONT
185.16.148.0/22    # ODNOKLASSNIKI-FRONT
185.16.244.0/22    # ODNOKLASSNIKI-FRONT
185.32.249.63      # sun2.userapi.com
185.86.144.0/22    # VKCS
185.100.104.0/22   # ODNOKLASSNIKI-FRONT
185.130.112.0/22   # VKCS
185.131.68.0/22    # RU-NETBRIDGE-20151215
185.180.200.0/22   # RU-NETBRIDGE-20161207
185.187.63.0/24    # VK-FRONT
185.226.52.0/22    # ODNOKLASSNIKI-FRONT
185.241.192.0/22   # VKCS
188.93.56.0/21     # VK-FRONT
188.225.23.170     # vk-play.ru
193.168.47.254     # beget.com
193.203.40.0/22    # ODNOKLASSNIKI-FRONT
194.186.63.0/24    # RU-SOVINTEL-MSK-MAILRU-OFFICE-NET
195.211.20.0/22    # RU-NETBRIDGE-20090909
195.218.190.0/23   # RU-SOVINTEL-MSK-MAILRU-OFFICE-NET
209.85.233.188     # mtalk.google.com
212.111.84.0/22    # KZ-VKTECH-19990209
212.233.72.0/21    # KZ-VKTECH-20000828
212.233.88.0/21    # KZ-VKTECH-20000828
212.233.96.0/22    # KZ-VKTECH-20000828
212.233.120.0/22   # KZ-VKTECH-20000828
213.59.253.7       # gosuslugi.ru
213.59.254.7       # gosuslugi.ru
213.219.212.0/22   # VKCS
217.16.16.0/20     # VKCS
217.20.144.0/20    # ODNOKLASSNIKI-FRONT
217.69.128.0/20    # VK-FRONT
217.174.188.0/22   # ODNOKLASSNIKI-FRONT
```

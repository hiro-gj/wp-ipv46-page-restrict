# 「WordPress」ページごとにIPアドレスによるアクセス制限をかける（IPv6・IPv4両対応）

## 使い方
1. 次のように配置する
```
./wp-content/themes/[テーマ名]/

  └ functions.php            ← 「functions.phpの最終行に追加貼付するコード.txt」を追加する

  └ get_ip-and-slug_list.php ← 配置

  └ ip-check.php             ← 配置
```

2. 固定ページ「ip_allowed」（非公開）を作成し
   <br>本文に次の様に「対象とするページスラッグ => 許可するIPアドレス」を書く
```
/*
* 対応コメント:
*   # 行コメント
*   // 行コメント
*   [ブロックコメント] 例: / * ... * /
*   <!-- HTMLコメント -->
*/
restricted-page-1 => 203.0.113.10,203.0.113.10/32
restricted-page-2 => 2001:db8::1,2001:db8::/64
```



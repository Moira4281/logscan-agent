#!/bin/bash
# 打包 Skill 制品包为 ZIP（AgentArts 平台导入格式）
# 用法：bash skills/build_skills.sh
# 输出：skills/dist/<skill-name>.zip
set -e
cd "$(dirname "$0")"

mkdir -p dist
rm -f dist/*.zip

for skill_dir in */; do
  skill_dir="${skill_dir%/}"
  [ "$skill_dir" = "dist" ] && continue
  [ ! -f "$skill_dir/SKILL.md" ] && continue

  python -c "
import sys, zipfile, os
src = '$skill_dir'
dst = 'dist/${skill_dir}.zip'
with zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED) as zf:
    for root, _, files in os.walk(src):
        for f in files:
            if f.endswith('.pyc') or '__pycache__' in root:
                continue
            p = os.path.join(root, f)
            zf.write(p, os.path.relpath(p, '.'))
print('  OK ${skill_dir}.zip')
"
done

echo ""
echo "打包完成。ZIP 文件在 skills/dist/ 下。"
echo "导入方式：AgentArts 控制台 → 资产广场 → Skill → 导入"
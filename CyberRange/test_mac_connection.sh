#!/bin/bash
echo "=== Mac连接测试脚本 ==="
echo ""
echo "1. 检查SSD挂载:"
if [ -d "/mnt/mypassport/cyberrange_data" ]; then
    echo "  ✅ SSD已挂载"
    echo "  📊 数据大小: $(du -sh /mnt/mypassport/cyberrange_data/ | cut -f1)"
else
    echo "  ❌ SSD未挂载，请检查连接"
fi

echo ""
echo "2. 检查关键数据:"
echo "  Balanced数据: $(ls /mnt/mypassport/cyberrange_data/runs/A_no_suri/ 2>/dev/null | wc -l) 次运行"
echo "  Group A数据: $(ls /mnt/mypassport/cyberrange_data/runs/suricata_validation/no_suri/ 2>/dev/null | wc -l) 次运行"
echo "  Group B数据: $(ls /mnt/mypassport/cyberrange_data/runs/suricata_validation/with_suri/ 2>/dev/null | wc -l) 次运行"

echo ""
echo "3. 检查符号链接:"
echo "  logs -> SSD: $(ls -la logs/ | grep mypassport | wc -l) 个链接"
echo "  output -> SSD: $(ls -la output/ | grep mypassport | wc -l) 个链接"
echo "  evaluation -> SSD: $(ls -la evaluation/ | grep mypassport | wc -l) 个链接"

# 配置文件对比分析：large_scale_2day_dataset.yaml vs test_2day_config.yaml

## 📊 攻击类型和百分比对比

### large_scale_2day_dataset.yaml (600秒，10分钟测试版)
**攻击分配 (总共15%)**:
- sql_injection_continuous: 4.0% (每25秒)
- xss_continuous: 2.5% (每40秒)
- authentication_bypass_continuous: 1.5% (每67秒)
- directory_traversal_continuous: 2.0% (每50秒)
- command_injection_continuous: 2.0% (每50秒)
- file_discovery_continuous: 2.0% (每50秒)
- http_method_enum_continuous: 1.0% (每100秒)

**良性流量 (总共85%)**:
- enterprise_business_traffic: 50%
- automated_systems_traffic: 20%
- mobile_app_traffic: 10%

### test_2day_config.yaml (300秒，5分钟测试版)
**攻击分配 (总共17%)**:
- sql_injection_test: 4.0% (每25秒)
- xss_test: 3.0% (每33秒)
- authentication_bypass_test: 2.0% (每50秒)
- directory_traversal_test: 2.0% (每50秒)
- command_injection_test: 2.0% (每50秒)
- file_discovery_test: 1.5% (每67秒)
- http_method_enum_test: 0.5% (每200秒)

**良性流量 (总共85%)**:
- test_business_operations: 60%
- test_api_traffic: 15%
- test_mobile_access: 10%

## ⚖️ 相似性分析

### ✅ 相似之处:
1. **攻击类型完全一致** - 都包含全部7种攻击类型
2. **攻击百分比基本相似** - 主要攻击类型比例接近
3. **良性流量总比例相同** - 都是80%+的良性流量
4. **配置结构相同** - 基础设施、数据收集、hooks完全相同

### ⚠️ 差异之处:
1. **时长不同**: large_scale(600s) vs test(300s)
2. **攻击payload范围**:
   - large_scale: `lines: "all"` (所有payload)
   - test: `lines: [1, 2]` (只有前2个payload)
3. **攻击间隔控制**:
   - large_scale: 有`script_args`包含`--interval`和`--max-payloads`
   - test: 没有script_args，依赖动态生成
4. **良性流量参数**:
   - large_scale: 使用`--frequency`参数
   - test: 使用`--intensity`参数 (不支持!)

## 🚨 发现的问题

### 问题1: test配置中的--intensity参数
test_2day_config.yaml中使用了`--intensity`参数，但`benign.sh`不支持此参数！
```yaml
script_args: ["--target", "http://fancystore.com", "--behavior", "business_test", "--intensity", "normal"]
```

### 问题2: 缺少新的timing控制参数
test配置没有使用我们新实现的`--interval`和`--max-payloads`参数。

## 🎯 结论

**test_2day_config.yaml作为large_scale预备测试是否合理？**

### ✅ 合理的地方:
1. **攻击类型覆盖完整** - 测试所有7种攻击类型
2. **比例基本相符** - 攻击/良性比例接近真实scenario
3. **时长适中** - 5分钟快速验证vs 10分钟正式测试
4. **基础设施相同** - 完全相同的Docker配置

### ❌ 需要修复的问题:
1. **benign traffic会失败** - `--intensity`参数不支持
2. **缺少新参数验证** - 没有测试`--interval`和`--max-payloads`
3. **payload范围受限** - 只测试前2个payload，不够全面

## 🔧 建议的修复方案

要让test_2day_config.yaml成为合理的预备测试，需要：

1. **移除--intensity参数**，使用支持的参数
2. **添加新的timing控制参数**到攻击配置中
3. **可选择扩大payload范围**，比如改为`[1, 3]`或`[1, 5]`

修复后，这将是一个很好的large_scale预备测试配置！

#!/bin/bash

# 脚本名称：run_experiment.sh
# 用途：在Ubuntu上重复运行 server -> verifier -> client 并统计tag_collection.size() >= 2的比例和verifyResult=1的比例
# 使用方法：在项目根目录下执行 ./run_experiment.sh [运行次数]

# 设置运行次数，默认为10次
RUN_COUNT=${1:-10}

# 报告文件名
REPORT_FILE="experiment_report_$(date +%Y%m%d_%H%M%S).txt"

# 进入build目录
cd build || { 
    echo "Error: build目录不存在" | tee -a "$REPORT_FILE"
    exit 1 
}

# 确保可执行文件存在
if [[ ! -f server ]] || [[ ! -f verifier ]] || [[ ! -f client ]]; then
    echo "Error: 可执行文件不存在，请先运行cmake和make" | tee -a "$REPORT_FILE"
    exit 1
fi

# 统计变量
total_runs=0
tag_ge_2_count=0
verify_success_count=0

# 临时文件用于存储输出
temp_output=$(mktemp)

{
    echo "开始实验，运行次数: $RUN_COUNT"
    echo "=========================================="
} >> "$REPORT_FILE"

for ((i=1; i<=RUN_COUNT; i++)); do
    echo "第 $i 次运行..." >> "$REPORT_FILE"
    
    # 清空临时文件
    > "$temp_output"
    
    # 启动server在新的terminal中，并捕获其输出
    gnome-terminal --title="Server $i" -- bash -c "./server 2>&1 | tee -a '$temp_output'" >/dev/null 2>&1 &
    SERVER_PID=$!
    
    # 等待server启动
    sleep 2
    
    # 启动verifier在新的terminal中
    gnome-terminal --title="Verifier $i" -- bash -c "./verifier 2>&1" >/dev/null 2>&1 &
    VERIFIER_PID=$!
    
    # 等待verifier启动
    sleep 2
    
    # 启动client在新的terminal中
    gnome-terminal --title="Client $i" -- bash -c "./client 2>&1" >/dev/null 2>&1 &
    CLIENT_PID=$!
    
    # 等待所有进程完成
    echo "等待进程完成..." >> "$REPORT_FILE"
    sleep 3  # 根据你的程序实际运行时间调整
    
    # 从server输出中提取tag_collection.size()信息
    if grep -q "match tag number:" "$temp_output"; then
        total_runs=$((total_runs + 1))
        
        # 提取匹配的tag数量
        tag_count=$(grep "match tag number:" "$temp_output" | awk '{print $4}')
        
        echo "第 $i 次运行 - match tag number: $tag_count" >> "$REPORT_FILE"
        
        # 检查是否大于等于2
        if [[ $tag_count -ge 2 ]]; then
            tag_ge_2_count=$((tag_ge_2_count + 1))
            echo "  ✓ tag_collection.size() >= 2" >> "$REPORT_FILE"
        else
            echo "  ✗ tag_collection.size() < 2" >> "$REPORT_FILE"
        fi
        
        # 提取verifyResult信息（server.cpp第441行）
        if grep -q "Verify result for the correct password and verify epoch: success" "$temp_output"; then
            verify_success_count=$((verify_success_count + 1))
            echo "  ✓ verifyResult = 1 (验证成功)" >> "$REPORT_FILE"
        elif grep -q "Verify result for the correct password and verify epoch: failure" "$temp_output"; then
            echo "  ✗ verifyResult = 0 (验证失败)" >> "$REPORT_FILE"
        else
            echo "  ? verifyResult信息未找到" >> "$REPORT_FILE"
        fi
    else
        echo "第 $i 次运行 - 未找到tag_collection信息" >> "$REPORT_FILE"
    fi
    
    # 清理进程（确保没有残留）
    pkill -f "./server" 2>/dev/null || true
    pkill -f "./verifier" 2>/dev/null || true
    pkill -f "./client" 2>/dev/null || true
    
    # 关闭所有相关terminal窗口
    wmctrl -l 2>/dev/null | grep -E "Server $i|Verifier $i|Client $i" | awk '{print $1}' | while read id; do
        wmctrl -i -c "$id" 2>/dev/null || true
    done
    
    echo "------------------------------------------" >> "$REPORT_FILE"
    sleep 1  # 短暂延迟，确保清理完成
done

# 删除临时文件
rm -f "$temp_output"

# 计算比例
tag_ge_2_percentage=0
verify_success_percentage=0

if [[ $total_runs -gt 0 ]]; then
    tag_ge_2_percentage=$(echo "scale=2; $tag_ge_2_count * 100 / $total_runs" | bc)
    verify_success_percentage=$(echo "scale=2; $verify_success_count * 100 / $total_runs" | bc)
fi

# 生成详细报告
{
    echo "=========================================="
    echo "实验完成!"
    echo "总有效运行次数: $total_runs"
    echo ""
    echo "统计结果1: tag_collection.size() >= 2"
    echo "----------------------------------------"
    echo "出现次数: $tag_ge_2_count"
    echo "比例: $tag_ge_2_percentage%"
    echo ""
    echo "统计结果2: verifyResult == 1 (验证成功)"
    echo "----------------------------------------"
    echo "验证成功次数: $verify_success_count"
    echo "比例: $verify_success_percentage%"
    echo ""
    echo "总结:"
    echo "tag_collection.size() >= 2 且 verifyResult == 1 的比例: "
    echo "=========================================="
} >> "$REPORT_FILE"

# 只在终端显示最终摘要
echo "=========================================="
echo "实验完成! 详细结果已保存到: $REPORT_FILE"
echo "总运行次数: $RUN_COUNT"
echo "有效运行次数: $total_runs"
echo ""
echo "tag_collection.size() >= 2 的比例: $tag_ge_2_percentage% ($tag_ge_2_count/$total_runs)"
echo "verifyResult == 1 的比例: $verify_success_percentage% ($verify_success_count/$total_runs)"
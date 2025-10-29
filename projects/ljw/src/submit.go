package src

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"ebpf/bpf"

	. "ebpf/model"
	. "ebpf/util"

	"github.com/gofiber/fiber/v2"
)

func Submit(data Data) (JudgeResult, error) {
	result := JudgeResult{}
	PrintData(data)

	codePath := "out/code.c"
	err := SaveCode(codePath, data.Code)
	if err != nil {
		return result, err
	}

	executePath := "out/execute"
	resultStatus, _ := BuildCode(codePath, executePath)
	if resultStatus == JudgeCompileError {
		return JudgeResult{Status: JudgeCompileError}, nil
	}

	result, err = Judge(data)
	if err != nil {
		return result, err
	}

	return result, nil
}

func SaveCode(codePath, code string) error {
	err := os.WriteFile(codePath, []byte(code), os.ModePerm)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, fmt.Sprintf("[Code Save Failed]\nError writing code.c file\n%v", err))
	}
	return nil
}

func BuildCode(codePath, executePath string) (JudgeStatusEnum, error) {
	cmd := exec.Command("gcc", codePath, "-o", executePath, "-O2", "-Wall", "-lm", "-static", "-std=gnu99")

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Code Build Failed]\n%s\n%v\n", string(output), err)
		return JudgeCompileError, nil
	}
	return JudgeCorrect, nil
}

func Judge(data Data) (JudgeResult, error) {
	result := JudgeResult{}
	isWrong := false
	isRuntimeError := false
	var totalUsedTime int64 = 0
	var totalUsedMemory int64 = 0
	testCaseCount := int64(len(data.Inputs))

	manager, err := bpf.NewEBPFManager()
	if err != nil {
		return result, fmt.Errorf("eBPF 매니저 생성 실패: %w", err)
	}
	defer manager.Close()

	for i := 0; i < len(data.Inputs); i++ {
		inputContents := []byte(data.Inputs[i])
		expectedOutput := []byte(data.Outputs[i])

		runCmd := []string{"./out/execute"}
		execResult, actualOutput, usedTime, usedMemory, err := executeProgram(manager, runCmd, inputContents, data.TimeLimit, data.MemoryLimit, i+1)
		if execResult == JudgeTimeOut {
			result.Status = JudgeTimeOut
			return result, nil
		}

		if err != nil {
			if execResult == JudgeRuntimeError {
				isRuntimeError = true
			}
			continue
		}

		if !checkDifference(actualOutput, expectedOutput) {
			isWrong = true
		}

		fmt.Printf("사용 시간: %dms\n", usedTime)
		fmt.Printf("사용 메모리: %d bytes\n", usedMemory)

		totalUsedTime += usedTime
		totalUsedMemory += usedMemory
	}

	if isRuntimeError {
		result.Status = JudgeRuntimeError
		return result, nil
	}

	result.UsedTime = totalUsedTime / testCaseCount
	result.UsedMemory = totalUsedMemory

	if isWrong {
		result.Status = JudgeWrong
		return result, nil
	}

	result.Status = JudgeCorrect
	return result, nil
}

func executeProgram(manager *bpf.EBPFManager, runCmd []string, inputContents []byte, timeLimit, memoryLimit int64, testCaseNum int) (JudgeStatusEnum, []byte, int64, int64, error) {
	fmt.Printf("=====%d번 테스트케이스 실행 중=====\n", testCaseNum)

	var err error // Declare err here

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeLimit)*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, runCmd[0], runCmd[1:]...)
	cmd.Stdin = bytes.NewReader(inputContents)

	var outputBuffer bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &outputBuffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return JudgeRuntimeError, nil, 0, 0, err
	}

	pid := uint32(cmd.Process.Pid)

	// Start monitoring with the actual PID after the process has started
	if err := manager.StartMonitoring(pid); err != nil {
		return JudgeRuntimeError, nil, 0, 0, fmt.Errorf("메모리 모니터링 시작 실패: %w", err)
	}

	debugPIDs, debugErr := manager.GetDebugPIDs()
	if debugErr != nil {
		fmt.Fprintf(os.Stderr, "디버그 PID 조회 실패: %v\n", debugErr)
	} else {
		fmt.Printf("eBPF PID (from map): %d, Target PID (from map): %d\n", debugPIDs.EbpfPID, debugPIDs.TargetPID)
	}

	startTime := time.Now()
	err = cmd.Wait()
	usedTime := time.Since(startTime).Milliseconds()

	usedMemory, memErr := manager.GetPeakMemory(pid)
	fmt.Printf("Monitoring PID: %d\n", pid)
	if memErr != nil {
		usedMemory = 0
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return JudgeTimeOut, nil, usedTime, usedMemory, ctx.Err()
	}

	if err != nil {
		runtimeError := fmt.Errorf("런타임 오류: %w, 상세 정보: %s", err, stderr.String())
		return JudgeRuntimeError, nil, usedTime, usedMemory, runtimeError
	}

	if stderr.Len() > 0 {
		return JudgeRuntimeError, nil, usedTime, usedMemory, fmt.Errorf("런타임 오류 발생: %s", stderr.String())
	}

	output := outputBuffer.Bytes()
	return JudgeCorrect, output, usedTime, usedMemory, nil
}

func checkDifference(executeContents, outputContents []byte) bool {
	fmt.Println("예상 결과\n", string(outputContents))
	fmt.Println("실제 결과\n", string(executeContents))

	if !bytes.Equal(executeContents, outputContents) {
		fmt.Println("결과가 일치하지 않습니다.")
		return false
	}

	fmt.Println("결과가 일치합니다!")
	return true
}

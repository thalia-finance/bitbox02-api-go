// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type simulatorScreenType string

const (
	simulatorScreenConfirm            simulatorScreenType = "confirm"
	simulatorScreenTransactionAddress simulatorScreenType = "transaction_address"
	simulatorScreenTransactionFee     simulatorScreenType = "transaction_fee"
	simulatorScreenStatus             simulatorScreenType = "status"
	simulatorScreenSwap               simulatorScreenType = "swap"

	simulatorScreenFieldTitle   = "TITLE"
	simulatorScreenFieldBody    = "BODY"
	simulatorScreenFieldAmount  = "AMOUNT"
	simulatorScreenFieldAddress = "ADDRESS"
	simulatorScreenFieldFee     = "FEE"
	simulatorScreenFieldFrom    = "FROM"
	simulatorScreenFieldTo      = "TO"

	simulatorTestTransactionAmount = "0.20000000 TBTC"
	simulatorTestTransactionTitle  = "Transaction"
)

// simulatorScreen is the screen representation observable in simulator stdout.
type simulatorScreen struct {
	Type    simulatorScreenType `json:"type"`
	Title   string              `json:"title,omitempty"`
	Body    string              `json:"body,omitempty"`
	Amount  string              `json:"amount,omitempty"`
	Address string              `json:"address,omitempty"`
	Fee     string              `json:"fee,omitempty"`
	From    string              `json:"from,omitempty"`
	To      string              `json:"to,omitempty"`
}

type simulatorScreenCapture struct {
	stdout     *simulatorStdout
	checkpoint int
}

func newSimulatorScreenCapture(stdout *simulatorStdout) *simulatorScreenCapture {
	return &simulatorScreenCapture{
		stdout:     stdout,
		checkpoint: stdout.checkpoint(),
	}
}

func (capture *simulatorScreenCapture) screensSinceCheckpoint() ([]simulatorScreen, error) {
	stdout, err := capture.stdout.snapshot(capture.checkpoint)
	if err != nil {
		return nil, err
	}
	return parseSimulatorScreens(stdout)
}

func (capture *simulatorScreenCapture) waitForTerminalStatus(
	stableFor time.Duration,
	timeout time.Duration,
) ([]simulatorScreen, error) {
	stdout, err := capture.stdout.wait(
		capture.checkpoint,
		func(snapshot string) bool {
			screens, err := parseSimulatorScreens(snapshot)
			return err == nil && len(screens) > 0 && screens[len(screens)-1].Type == simulatorScreenStatus
		},
		stableFor,
		timeout,
	)
	if err != nil {
		return nil, err
	}
	return parseSimulatorScreens(stdout)
}

type simulatorScreenFormat struct {
	end        string
	fields     []string
	screenType simulatorScreenType
}

var simulatorScreenFormats = map[string]simulatorScreenFormat{
	"CONFIRM SCREEN START": {
		end:        "CONFIRM SCREEN END",
		fields:     []string{simulatorScreenFieldTitle, simulatorScreenFieldBody},
		screenType: simulatorScreenConfirm,
	},
	"CONFIRM TRANSACTION ADDRESS SCREEN START": {
		end:        "CONFIRM TRANSACTION ADDRESS SCREEN END",
		fields:     []string{simulatorScreenFieldAmount, simulatorScreenFieldAddress},
		screenType: simulatorScreenTransactionAddress,
	},
	"CONFIRM TRANSACTION FEE SCREEN START": {
		end:        "CONFIRM TRANSACTION FEE SCREEN END",
		fields:     []string{simulatorScreenFieldAmount, simulatorScreenFieldFee},
		screenType: simulatorScreenTransactionFee,
	},
	"STATUS SCREEN START": {
		end:        "STATUS SCREEN END",
		fields:     []string{simulatorScreenFieldTitle},
		screenType: simulatorScreenStatus,
	},
	"CONFIRM SWAP SCREEN START": {
		end:        "CONFIRM SWAP SCREEN END",
		fields:     []string{simulatorScreenFieldTitle, simulatorScreenFieldFrom, simulatorScreenFieldTo},
		screenType: simulatorScreenSwap,
	},
}

func parseSimulatorScreenFields(lines []string, fields []string) (map[string]string, error) {
	result := make(map[string]string, len(fields))
	lineIndex := 0

	for fieldIndex, field := range fields {
		if lineIndex >= len(lines) {
			return nil, fmt.Errorf("missing %s field", field)
		}

		prefix := field + ": "
		if !strings.HasPrefix(lines[lineIndex], prefix) {
			return nil, fmt.Errorf("expected %q, got %q", prefix, lines[lineIndex])
		}

		valueLines := []string{strings.TrimPrefix(lines[lineIndex], prefix)}
		lineIndex++
		if fieldIndex+1 < len(fields) {
			nextPrefix := fields[fieldIndex+1] + ": "
			for lineIndex < len(lines) && !strings.HasPrefix(lines[lineIndex], nextPrefix) {
				valueLines = append(valueLines, lines[lineIndex])
				lineIndex++
			}
		} else {
			valueLines = append(valueLines, lines[lineIndex:]...)
			lineIndex = len(lines)
		}
		result[field] = strings.Join(valueLines, "\n")
	}

	return result, nil
}

func parseSimulatorStatusScreenFields(lines []string) (map[string]string, error) {
	if len(lines) == 0 {
		return nil, fmt.Errorf("missing %s field", simulatorScreenFieldTitle)
	}
	prefix := simulatorScreenFieldTitle + ": "
	if !strings.HasPrefix(lines[0], prefix) {
		return nil, fmt.Errorf("expected %q, got %q", prefix, lines[0])
	}
	return map[string]string{
		simulatorScreenFieldTitle: strings.TrimPrefix(lines[0], prefix),
		simulatorScreenFieldBody:  strings.Join(lines[1:], "\n"),
	}, nil
}

func newSimulatorScreen(screenType simulatorScreenType, fields map[string]string) simulatorScreen {
	return simulatorScreen{
		Type:    screenType,
		Title:   fields[simulatorScreenFieldTitle],
		Body:    fields[simulatorScreenFieldBody],
		Amount:  fields[simulatorScreenFieldAmount],
		Address: fields[simulatorScreenFieldAddress],
		Fee:     fields[simulatorScreenFieldFee],
		From:    fields[simulatorScreenFieldFrom],
		To:      fields[simulatorScreenFieldTo],
	}
}

func isSimulatorScreenEnd(line string) bool {
	for _, format := range simulatorScreenFormats {
		if line == format.end {
			return true
		}
	}
	return false
}

func isSimulatorScreenMarker(line string) bool {
	return strings.HasSuffix(line, " SCREEN START") || strings.HasSuffix(line, " SCREEN END")
}

// parseSimulatorScreens extracts the structured UI screens from simulator stdout. Other simulator
// log lines are ignored, but recognized screen blocks must match the stdout UI stub format exactly.
func parseSimulatorScreens(stdout string) ([]simulatorScreen, error) {
	lines := strings.Split(stdout, "\n")
	result := []simulatorScreen{}

	for lineIndex := 0; lineIndex < len(lines); lineIndex++ {
		format, ok := simulatorScreenFormats[lines[lineIndex]]
		if !ok {
			if isSimulatorScreenMarker(lines[lineIndex]) {
				return nil, fmt.Errorf("unknown screen marker %q on line %d", lines[lineIndex], lineIndex+1)
			}
			continue
		}

		startLine := lineIndex + 1
		endLine := startLine
		for ; endLine < len(lines) && lines[endLine] != format.end; endLine++ {
			if _, nested := simulatorScreenFormats[lines[endLine]]; nested {
				return nil, fmt.Errorf("screen starting on line %d contains a nested screen on line %d", lineIndex+1, endLine+1)
			}
			if isSimulatorScreenEnd(lines[endLine]) {
				return nil, fmt.Errorf("screen starting on line %d has unexpected end marker %q on line %d", lineIndex+1, lines[endLine], endLine+1)
			}
			if isSimulatorScreenMarker(lines[endLine]) {
				return nil, fmt.Errorf("screen starting on line %d has unexpected marker %q on line %d", lineIndex+1, lines[endLine], endLine+1)
			}
		}
		if endLine == len(lines) {
			return nil, fmt.Errorf("screen starting on line %d is missing %q", lineIndex+1, format.end)
		}

		var fields map[string]string
		var err error
		if format.screenType == simulatorScreenStatus {
			fields, err = parseSimulatorStatusScreenFields(lines[startLine:endLine])
		} else {
			fields, err = parseSimulatorScreenFields(lines[startLine:endLine], format.fields)
		}
		if err != nil {
			return nil, fmt.Errorf("screen starting on line %d: %w", lineIndex+1, err)
		}
		result = append(result, newSimulatorScreen(format.screenType, fields))
		lineIndex = endLine
	}

	return result, nil
}

func TestParseSimulatorScreens(t *testing.T) {
	stdout := `simulator startup log
CONFIRM SCREEN START
TITLE: Memo
BODY: first line

third line
CONFIRM SCREEN END
CONFIRM TRANSACTION ADDRESS SCREEN START
AMOUNT: 0.20000000 TBTC
ADDRESS: This BitBox (same account): tb1q example
CONFIRM TRANSACTION ADDRESS SCREEN END
CONFIRM TRANSACTION FEE SCREEN START
AMOUNT: 0.20000000 TBTC
FEE: 0.00001000 TBTC
CONFIRM TRANSACTION FEE SCREEN END
STATUS SCREEN START
TITLE: Transaction
signed
STATUS SCREEN END
CONFIRM SWAP SCREEN START
TITLE: Confirm swap
FROM: 1.0 BTC
on Bitcoin
TO: 20.0 ETH
on Ethereum
CONFIRM SWAP SCREEN END
unrelated trailing log
`

	screens, err := parseSimulatorScreens(stdout)
	require.NoError(t, err)
	require.Equal(t, []simulatorScreen{
		{
			Type:  simulatorScreenConfirm,
			Title: "Memo",
			Body:  "first line\n\nthird line",
		},
		{
			Type:    simulatorScreenTransactionAddress,
			Amount:  simulatorTestTransactionAmount,
			Address: "This BitBox (same account): tb1q example",
		},
		{
			Type:   simulatorScreenTransactionFee,
			Amount: simulatorTestTransactionAmount,
			Fee:    "0.00001000 TBTC",
		},
		{
			Type:  simulatorScreenStatus,
			Title: simulatorTestTransactionTitle,
			Body:  "signed",
		},
		{
			Type:  simulatorScreenSwap,
			Title: "Confirm swap",
			From:  "1.0 BTC\non Bitcoin",
			To:    "20.0 ETH\non Ethereum",
		},
	}, screens)
}

func TestSimulatorScreenJSON(t *testing.T) {
	encoded, err := json.Marshal([]simulatorScreen{
		{Type: simulatorScreenConfirm, Title: "OP_RETURN", Body: "hello world"},
		{
			Type:    simulatorScreenTransactionAddress,
			Amount:  simulatorTestTransactionAmount,
			Address: "Test Merchant",
		},
		{Type: simulatorScreenStatus, Title: simulatorTestTransactionTitle, Body: "confirmed"},
	})
	require.NoError(t, err)
	require.JSONEq(t, `[
		{"type":"confirm","title":"OP_RETURN","body":"hello world"},
		{"type":"transaction_address","amount":"0.20000000 TBTC","address":"Test Merchant"},
		{"type":"status","title":"Transaction","body":"confirmed"}
	]`, string(encoded))
}

func TestSimulatorScreenCaptureCheckpoint(t *testing.T) {
	stdout := newSimulatorStdout()
	_, err := stdout.WriteString(`CONFIRM SCREEN START
TITLE: Setup
BODY: Before checkpoint
CONFIRM SCREEN END
`)
	require.NoError(t, err)
	capture := newSimulatorScreenCapture(stdout)
	_, err = stdout.WriteString(`STATUS SCREEN START
TITLE: Signed
STATUS SCREEN END
`)
	require.NoError(t, err)

	screens, err := capture.screensSinceCheckpoint()
	require.NoError(t, err)
	require.Equal(t, []simulatorScreen{{Type: simulatorScreenStatus, Title: "Signed"}}, screens)
}

func TestSimulatorScreenCaptureWaitForTerminalStatus(t *testing.T) {
	stdout := newSimulatorStdout()
	capture := newSimulatorScreenCapture(stdout)

	go func() {
		_, _ = stdout.WriteString(`CONFIRM SCREEN START
TITLE: Confirm
BODY: transaction
CONFIRM SCREEN END
`)
		time.Sleep(10 * time.Millisecond)
		_, _ = stdout.WriteString(`STATUS SCREEN START
TITLE: Transaction
confirmed
STATUS SCREEN END
`)
	}()

	screens, err := capture.waitForTerminalStatus(5*time.Millisecond, time.Second)
	require.NoError(t, err)
	require.Equal(t, []simulatorScreen{
		{Type: simulatorScreenConfirm, Title: "Confirm", Body: "transaction"},
		{Type: simulatorScreenStatus, Title: simulatorTestTransactionTitle, Body: "confirmed"},
	}, screens)
}

func TestParseSimulatorScreensRejectsMalformedBlocks(t *testing.T) {
	tests := map[string]string{
		"missing end marker": `
CONFIRM SCREEN START
TITLE: Title
BODY: Body`,
		"missing field": `
CONFIRM TRANSACTION FEE SCREEN START
AMOUNT: 1 BTC
CONFIRM TRANSACTION FEE SCREEN END`,
		"wrong field order": `
CONFIRM SWAP SCREEN START
FROM: 1 BTC
TITLE: Swap
TO: 20 ETH
CONFIRM SWAP SCREEN END`,
		"extra data before fields": `
CONFIRM SCREEN START
unexpected
TITLE: Title
BODY: Body
CONFIRM SCREEN END`,
		"nested screen": `
CONFIRM SCREEN START
TITLE: Outer
BODY: Body
STATUS SCREEN START
TITLE: Inner
STATUS SCREEN END
CONFIRM SCREEN END`,
		"mismatched end marker": `
CONFIRM SCREEN START
TITLE: Title
BODY: Body
STATUS SCREEN END
CONFIRM SCREEN END`,
		"unknown start marker": `
FUTURE SCREEN START
TITLE: Future
FUTURE SCREEN END`,
		"unknown end marker": `
FUTURE SCREEN END`,
	}

	for name, stdout := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := parseSimulatorScreens(stdout)
			require.Error(t, err)
		})
	}
}

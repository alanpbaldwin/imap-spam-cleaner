package inbox

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dominicgisler/imap-spam-cleaner/app"
	"github.com/dominicgisler/imap-spam-cleaner/database"
	"github.com/dominicgisler/imap-spam-cleaner/imap"
	"github.com/dominicgisler/imap-spam-cleaner/logx"
	"github.com/dominicgisler/imap-spam-cleaner/provider"
	"github.com/go-co-op/gocron/v2"
)

func Schedule(ctx app.Context) {

	s, err := gocron.NewScheduler()
	if err != nil {
		logx.Errorf("Could not create scheduler: %v", err)
		return
	}

	for i, inbox := range ctx.Config.Inboxes {
		logx.Infof("Scheduling inbox %s (%s)", inbox.Username, inbox.Schedule)
		prov, ok := ctx.Config.Providers[inbox.Provider]
		if !ok {
			logx.Errorf("Invalid provider %s for inbox %d", inbox.Provider, i)
			continue
		}
		if _, err = s.NewJob(
			gocron.CronJob(inbox.Schedule, false),
			gocron.NewTask(processInbox, ctx, inbox, prov),
		); err != nil {
			logx.Errorf("Could not schedule inbox %s (%s): %v", inbox.Username, inbox.Schedule, err)
		}
	}

	s.Start()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	sig := <-ch
	logx.Debugf("Received %s, shutting down", sig.String())

	if err = s.Shutdown(); err != nil {
		logx.Errorf("Could not shutdown scheduler: %v ", err)
	}
}

func RunAllInboxes(ctx app.Context) {
	for i, inbox := range ctx.Config.Inboxes {
		logx.Infof("Processing inbox %s", inbox.Username)
		prov, ok := ctx.Config.Providers[inbox.Provider]
		if !ok {
			logx.Errorf("Invalid provider %s for inbox %d", inbox.Provider, i)
			continue
		}
		processInbox(ctx, inbox, prov)
	}
}

func processInbox(ctx app.Context, inbox app.Inbox, prov app.Provider) {

	var err error
	var msgs []imap.Message
	var p provider.Provider
	var im *imap.Imap
	var n int
	var run database.Run

	logx.Infof("Handling %s", inbox.Username)
	run.StartedAt = time.Now()
	run.Inbox = inbox.Username

	if im, err = imap.New(inbox); err != nil {
		logx.Errorf("Could not load imap: %v\n", err)
		return
	}

	if msgs, err = im.LoadMessages(); err != nil {
		logx.Errorf("Could not load messages: %v\n", err)
		im.Close()
		return
	}
	logx.Infof("Loaded %d messages", len(msgs))
	run.MessageCount = len(msgs)

	// Close the IMAP connection before analysis. Provider calls (SpamAssassin,
	// AI) can take minutes when messages time out, causing the IMAP server to
	// drop the idle connection. A fresh connection is opened for the move phase.
	im.Close()

	p, err = provider.New(prov.Type)
	if err != nil {
		logx.Errorf("Could not load provider: %v\n", err)
		return
	}

	if err = p.Init(prov.Config); err != nil {
		logx.Errorf("Could not init provider: %v\n", err)
		return
	}

	// Phase 1: Analyze all messages, collect those to move
	var toMove []imap.Message
	for _, m := range msgs {
		if wl, ok := ctx.Config.Whitelists[inbox.Whitelist]; ok {
			trustedSender := false
			for _, rgx := range wl {
				if rgx.Match([]byte(m.From)) {
					trustedSender = true
					break
				}
			}
			if trustedSender {
				logx.Debugf("Skipping message #%d (%s) because of trusted sender (%s)", m.UID, m.Subject, m.From)
				run.SkippedCount++
				continue
			}
		}

		if n, err = p.Analyze(m); err != nil {
			logx.Errorf("Could not analyze message (%s): %v\n", m.Subject, err)
			run.FailedCount++
			continue
		}
		logx.Debugf("Spam score of message #%d (%s): %d/100", m.UID, m.Subject, n)

		if n >= inbox.MinScore {
			if ctx.Options.AnalyzeOnly {
				logx.Debugf("Analyze only mode, not moving message #%d", m.UID)
				continue
			}
			toMove = append(toMove, m)
		}
	}

	// Phase 2: Reconnect and move spam messages
	moved := 0
	if len(toMove) > 0 {
		if im, err = imap.New(inbox); err != nil {
			logx.Errorf("Could not reconnect to IMAP for move phase: %v\n", err)
			logx.Infof("Moved %d messages", moved)
			return
		}
		if err = im.SelectInbox(); err != nil {
			logx.Errorf("Could not select inbox for move phase: %v\n", err)
			im.Close()
			logx.Infof("Moved %d messages", moved)
			return
		}
		for _, m := range toMove {
			if err = im.MoveMessage(m.UID, inbox.Spam); err != nil {
				logx.Errorf("Could not move message (%s): %v\n", m.Subject, err)
				continue
			}
			moved++
		}
		im.Close()
	}
	logx.Infof("Moved %d messages", moved)
	run.MovedCount = moved

	// NB: no trailing im.Close() here — unlike upstream v0.8.2. In the two-phase
	// design the connection is already closed (line ~93 before analysis, or at
	// the end of Phase 2 after the move), so closing again would be a double-close.
	if !ctx.Options.AnalyzeOnly {
		run.FinishedAt = time.Now()
		if err = database.AddRun(&run); err != nil {
			logx.Errorf("Could not save run: %v\n", err)
		}
	}
}

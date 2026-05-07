package selfprotect

import (
	"context"
	"sync"
	"time"

	"github.com/Velocidex/ordereddict"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services/debug"
	"www.velocidex.com/golang/velociraptor/utils"
	"www.velocidex.com/golang/vfilter"
)

const checkInterval = 30 * time.Second

type SelfProtectionService struct {
	config_obj  *config_proto.Config
	logger      *logging.LogContext
	serviceName string
	paths       []string

	mu                    sync.Mutex
	serviceProtected      bool
	filesProtected        bool
	lastCheck             time.Time
	tamperingDetectedCount uint64
}

func (self *SelfProtectionService) applyProtections() {
	self.mu.Lock()
	defer self.mu.Unlock()

	if self.serviceName != "" {
		err := ApplyServiceProtection(self.serviceName)
		if err != nil {
			self.logger.Error(
				"SelfProtection: <red>Failed to protect service %v</>: %v",
				self.serviceName, err)
			self.serviceProtected = false
		} else {
			self.serviceProtected = true
			self.logger.Info(
				"SelfProtection: <green>Service %v protected</>",
				self.serviceName)
		}
	}

	if len(self.paths) > 0 {
		err := ApplyFileProtection(self.paths)
		if err != nil {
			self.logger.Error(
				"SelfProtection: <red>Failed to protect files</>: %v", err)
			self.filesProtected = false
		} else {
			self.filesProtected = true
			self.logger.Info(
				"SelfProtection: <green>Files protected</>: %v", self.paths)
		}
	}
}

func (self *SelfProtectionService) verifyProtections() {
	self.mu.Lock()
	defer self.mu.Unlock()

	self.lastCheck = utils.GetTime().Now()

	if self.serviceName != "" {
		protected, err := VerifyServiceProtection(self.serviceName)
		if err != nil {
			self.logger.Error(
				"SelfProtection: <red>Error verifying service protection</>: %v", err)
		} else if !protected {
			self.logger.Error(
				"SelfProtection: <red>Service tampering detected!</> Re-applying protection.")
			self.tamperingDetectedCount++
			self.serviceProtected = false

			self.mu.Unlock()
			ApplyServiceProtection(self.serviceName)
			self.mu.Lock()
			self.serviceProtected = true
		}
	}

	if len(self.paths) > 0 {
		tampered, err := VerifyFileProtection(self.paths)
		if err != nil {
			self.logger.Error(
				"SelfProtection: <red>Error verifying file protection</>: %v", err)
		} else if len(tampered) > 0 {
			self.logger.Error(
				"SelfProtection: <red>File tampering detected!</> Files: %v. Re-applying protection.",
				tampered)
			self.tamperingDetectedCount++
			self.filesProtected = false

			self.mu.Unlock()
			ApplyFileProtection(tampered)
			self.mu.Lock()
			self.filesProtected = true
		}
	}
}

func (self *SelfProtectionService) ProfileWriter(ctx context.Context,
	scope vfilter.Scope, output_chan chan vfilter.Row) {

	self.mu.Lock()
	defer self.mu.Unlock()

	output_chan <- ordereddict.NewDict().
		Set("ServiceName", self.serviceName).
		Set("ServiceProtected", self.serviceProtected).
		Set("FilesProtected", self.filesProtected).
		Set("ProtectedPaths", self.paths).
		Set("LastCheck", self.lastCheck).
		Set("TamperingDetectedCount", self.tamperingDetectedCount)
}

func StartSelfProtectionService(
	ctx context.Context,
	wg *sync.WaitGroup,
	config_obj *config_proto.Config) error {

	if config_obj.Client == nil || !config_obj.Client.EnableSelfProtection {
		return nil
	}

	logger := logging.GetLogger(config_obj, &logging.ClientComponent)

	var serviceName string
	if config_obj.Client.WindowsInstaller != nil {
		serviceName = config_obj.Client.WindowsInstaller.ServiceName
	}

	paths := GetProtectedPaths(config_obj)

	service := &SelfProtectionService{
		config_obj:  config_obj,
		logger:      logger,
		serviceName: serviceName,
		paths:       paths,
	}

	service.applyProtections()

	debug.RegisterProfileWriter(debug.ProfileWriterInfo{
		Name:          "SelfProtection",
		Description:   "Inspect status of self-protection",
		ProfileWriter: service.ProfileWriter,
		Categories:    []string{"Client"},
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer logger.Info("<red>Exiting</> self-protection service")

		logger.Info("<green>Starting</> self-protection monitoring (interval %v)", checkInterval)

		for {
			select {
			case <-ctx.Done():
				return

			case <-utils.GetTime().After(checkInterval):
				service.verifyProtections()
			}
		}
	}()

	return nil
}

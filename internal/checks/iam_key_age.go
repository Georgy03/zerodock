package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// maxKeyAgeDays is our security policy: an access key older than this is
// flagged, even if nothing else is wrong with it. Old keys are risky
// because the longer a secret exists, the more chances it's had to leak
// (committed to a public repo, left in a log file, saved on an old laptop,
// etc.), and rotating keys regularly limits how much damage a leaked key
// can do.
const maxKeyAgeDays = 90

func init() {
	Register(Check{
		ID:    "aws.iam.key_age",
		Title: "IAM access keys older than 90 days",
		Tier:  ProviderAttested,
		Run:   iamKeyAge,
	})
}

// iamKeyAge looks at every IAM user in the account and every access key
// (a username/password-like credential pair used by scripts and
// applications, instead of a human logging into the AWS website) that user
// has, flagging any key older than maxKeyAgeDays.
//
// Like the root MFA check, this is a GLOBAL check — IAM users and their
// keys aren't tied to a specific region — so we call the API once instead
// of looping over regions.
//
// now is passed in by the caller rather than read via time.Now() here —
// see the comment on Check.Run in types.go. This check is the reason that
// parameter exists: inside an enclave with no reliable clock, a wrong
// "now" would silently miscompute every key's age (a truly stale key
// could read as brand new, or vice versa), and this is the one check
// where that actually changes the pass/fail result.
func iamKeyAge(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
	client := iam.NewFromConfig(cfg)

	var findings []string
	count := 0

	// Step 1: page through every IAM user in the account.
	userPaginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for userPaginator.HasMorePages() {
		userPage, err := userPaginator.NextPage(ctx)
		if err != nil {
			return Result{Status: StatusError, Findings: []string{describeErr(err)}}, nil
		}

		for _, user := range userPage.Users {
			username := aws.ToString(user.UserName)

			// Step 2: for each user, page through their access keys.
			// A single user can have up to two active keys at once
			// (that's a normal AWS limit, used for safely rotating
			// from an old key to a new one).
			keyPaginator := iam.NewListAccessKeysPaginator(client, &iam.ListAccessKeysInput{UserName: user.UserName})
			for keyPaginator.HasMorePages() {
				keyPage, err := keyPaginator.NextPage(ctx)
				if err != nil {
					return Result{Status: StatusError, Findings: []string{fmt.Sprintf("user %s: %s", username, describeErr(err))}}, nil
				}

				for _, key := range keyPage.AccessKeyMetadata {
					count++

					if key.CreateDate == nil {
						// We can't tell how old it is, so skip
						// rather than guess.
						continue
					}

					// An INACTIVE key has already been turned off by
					// whoever owns it — it can't be used to
					// authenticate to AWS anymore, so its age isn't a
					// live security problem the way an old ACTIVE key
					// is. Skip it here instead of flagging it the
					// same as a key that's still usable.
					if key.Status != iamtypes.StatusTypeActive {
						continue
					}

					// How much time has passed since this key was
					// created, measured in whole days.
					age := now.Sub(*key.CreateDate)
					days := int(age.Hours() / 24)

					if days > maxKeyAgeDays {
						findings = append(findings, fmt.Sprintf(
							"user %s: active access key %s is %d days old",
							username,
							aws.ToString(key.AccessKeyId),
							days,
						))
					}
				}
			}
		}
	}

	status := StatusPass
	if len(findings) > 0 {
		status = StatusFail
	}
	return Result{Status: status, Findings: findings, Count: count}, nil
}

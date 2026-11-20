// Package agent is the node agent: it enrolls and attests the node with its
// TPM, holds the node identity, and serves workload identities to local
// processes over a Unix socket.
//
// A workload is identified by the kernel, never by what it claims: the
// systemd system service whose cgroup contains the connecting process and
// that process's UID. The agent forwards those to the control plane, which
// decides from policy whether the pair is a workload on this node. Policy
// gives each workload one service and UID and each service on a node at
// most one workload, so two services on one node never share an identity.
package agent

// SPDX-License-Identifier: GPL-2.0-only

#include <linux/pci.h>
#include <linux/irq.h>
#include <linux/version.h>

#include <linux/percpu-defs.h>
#include <linux/sched/clock.h>

#include "nvmev.h"
#include "pci.h"

#ifdef CONFIG_NVMEV_FAST_X86_IRQ_HANDLING
static int apicid_to_cpuid[256];

static void __init_apicid_to_cpuid(void)
{
	int i;
	for_each_possible_cpu(i) {
		apicid_to_cpuid[per_cpu(x86_cpu_to_apicid, i)] = i;
	}
}

static void __signal_irq(unsigned int irq)
{
	struct irq_data *irqd = irq_get_irq_data(irq);
	struct irq_cfg *irqc = irqd_cfg(irqd);

	unsigned int target = irqc->dest_apicid;
	unsigned int target_cpu = apicid_to_cpuid[target];

	NVMEV_DEBUG("vector %d, dest_apicid %d, target_cpu %d\n", irqc->vector, target, target_cpu);
	apic->send_IPI(target_cpu, irqc->vector);

	return;
}
#else
static void __signal_irq(unsigned int irq)
{
	struct irq_data *data = irq_get_irq_data(irq);
	struct irq_chip *chip = irq_data_get_irq_chip(data);

	BUG_ON(!chip->irq_retrigger);
	chip->irq_retrigger(data);

	return;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
static void __process_msi_irq(int msi_index)
{
	unsigned int virq = msi_get_virq(&nvmev_vdev->pdev->dev, msi_index);

	BUG_ON(virq == 0);
	__signal_irq(virq);
}
#else
static void __process_msi_irq(int msi_index)
{
	struct msi_desc *msi_desc, *tmp;

	for_each_msi_entry_safe(msi_desc, tmp, (&nvmev_vdev->pdev->dev)) {
		if (msi_desc->msi_attrib.entry_nr == msi_index) {
			__signal_irq(msi_desc->irq);
			return;
		}
	}
	NVMEV_INFO("Failed to send IPI\n");
	BUG_ON(!msi_desc);
}
#endif

void nvmev_signal_irq(int msi_index)
{
	if (nvmev_vdev->pdev->msix_enabled) {
		__process_msi_irq(msi_index);
	} else {
		nvmev_vdev->pcihdr->sts.is = 1;

		__signal_irq(nvmev_vdev->pdev->irq);
	}
}

/*
 * The host device driver can change multiple locations in the BAR.
 * In a real device, these changes are processed one after the other,
 * preserving their requesting order. However, in NVMeVirt, the changes
 * can be DETECTED with the dispatcher, obsecuring the order between
 * changes that are made between the checking loop. Thus, we have to
 * process the changes strategically, in an order that are supposed
 * to be...
 *
 * Also, memory barrier is not necessary here since BAR-related
 * operations are only processed by the dispatcher.
 */
void nvmev_proc_bars(void)
{
	volatile struct __nvme_bar *old_bar = nvmev_vdev->old_bar;
	volatile struct nvme_ctrl_regs *bar = nvmev_vdev->bar;
	struct nvmev_admin_queue *queue = nvmev_vdev->admin_q;
	unsigned int num_pages, i;

#if 0 /* Read-only register */
	if (old_bar->cap != bar->u_cap) {
		memcpy(&old_bar->cap, &bar->cap, sizeof(old_bar->cap));
	}
	if (old_bar->vs != bar->u_vs) {
		memcpy(&old_bar->vs, &bar->vs, sizeof(old_bar->vs));
	}
	if (old_bar->cmbloc != bar->u_cmbloc) {
		memcpy(&old_bar->cmbloc, &bar->cmbloc, sizeof(old_bar->cmbloc));
	}
	if (old_bar->cmbsz != bar->u_cmbsz) {
		memcpy(&old_bar->cmbsz, &bar->cmbsz, sizeof(old_bar->cmbsz));
	}
	if (old_bar->rsvd1 != bar->rsvd1) {
		memcpy(&old_bar->rsvd1, &bar->rsvd1, sizeof(old_bar->rsvd1));
	}
	if (old_bar->csts != bar->u_csts) {
		memcpy(&old_bar->csts, &bar->csts, sizeof(old_bar->csts));
	}
#endif
#if 0 /* Unused registers */
	if (old_bar->intms != bar->intms) {
		memcpy(&old_bar->intms, &bar->intms, sizeof(old_bar->intms));
	}
	if (old_bar->intmc != bar->intmc) {
		memcpy(&old_bar->intmc, &bar->intmc, sizeof(old_bar->intmc));
	}
	if (old_bar->nssr != bar->nssr) {
		memcpy(&old_bar->nssr, &bar->nssr, sizeof(old_bar->nssr));
	}
#endif
	if (old_bar->aqa != bar->u_aqa) {
		// Initalize admin queue
		NVMEV_DEBUG("AQA: 0x%x -> 0x%x\n", old_bar->aqa, bar->u_aqa);
		old_bar->aqa = bar->u_aqa;

		if (!queue) {
			queue = kzalloc(sizeof(struct nvmev_admin_queue), GFP_KERNEL);
			BUG_ON(queue == NULL);
			WRITE_ONCE(nvmev_vdev->admin_q, queue);
		} else {
			queue = nvmev_vdev->admin_q;
		}

		queue->cq_head = 0;
		queue->phase = 1;
		queue->sq_depth = bar->aqa.asqs + 1; /* asqs and acqs are 0-based */
		queue->cq_depth = bar->aqa.acqs + 1;

		nvmev_vdev->dbs[0] = nvmev_vdev->old_dbs[0] = 0;
		nvmev_vdev->dbs[1] = nvmev_vdev->old_dbs[1] = 0;

		goto out;
	}
	if (old_bar->asq != bar->u_asq) {
		if (queue == NULL) {
			/*
			 * asq/acq can't be updated later than aqa, but in an unlikely case, this
			 * can be triggered before an aqa update due to memory re-ordering and lack
			 * of barriers.
			 *
			 * If that's the case, simply run the loop again after a full barrier so
			 * that the aqa code (initializing the admin queue) can run prior to this.
			 */
			NVMEV_INFO("asq triggered before aqa, retrying\n");
			goto out;
		}

		NVMEV_DEBUG("ASQ: 0x%llx -> 0x%llx\n", old_bar->asq, bar->u_asq);
		old_bar->asq = bar->u_asq;

		if (queue->nvme_sq) {
			kfree(queue->nvme_sq);
			queue->nvme_sq = NULL;
		}

		queue->sq_depth = bar->aqa.asqs + 1; /* asqs and acqs are 0-based */

		num_pages = DIV_ROUND_UP(queue->sq_depth * sizeof(struct nvme_command), PAGE_SIZE);
		queue->nvme_sq = kcalloc(num_pages, sizeof(struct nvme_command *), GFP_KERNEL);
		BUG_ON(!queue->nvme_sq && "Error on setup admin submission queue");

		for (i = 0; i < num_pages; i++) {
			queue->nvme_sq[i] =
				page_address(pfn_to_page(nvmev_vdev->bar->u_asq >> PAGE_SHIFT) + i);
		}

		nvmev_vdev->dbs[0] = nvmev_vdev->old_dbs[0] = 0;

		goto out;
	}
	if (old_bar->acq != bar->u_acq) {
		if (queue == NULL) {
			// See comment above
			NVMEV_INFO("acq triggered before aqa, retrying\n");
			goto out;
		}

		NVMEV_DEBUG("ACQ: 0x%llx -> 0x%llx\n", old_bar->acq, bar->u_acq);
		old_bar->acq = bar->u_acq;

		if (queue->nvme_cq) {
			kfree(queue->nvme_cq);
			queue->nvme_cq = NULL;
		}

		queue->cq_depth = bar->aqa.acqs + 1; /* asqs and acqs are 0-based */

		num_pages =
			DIV_ROUND_UP(queue->cq_depth * sizeof(struct nvme_completion), PAGE_SIZE);
		queue->nvme_cq = kcalloc(num_pages, sizeof(struct nvme_completion *), GFP_KERNEL);
		BUG_ON(!queue->nvme_cq && "Error on setup admin completion queue");
		queue->cq_head = 0;

		for (i = 0; i < num_pages; i++) {
			queue->nvme_cq[i] =
				page_address(pfn_to_page(nvmev_vdev->bar->u_acq >> PAGE_SHIFT) + i);
		}

		nvmev_vdev->dbs[1] = nvmev_vdev->old_dbs[1] = 0;

		goto out;
	}
	if (old_bar->cc != bar->u_cc) {
		NVMEV_DEBUG("CC: 0x%x:%x -> 0x%x:%x\n", old_bar->cc, old_bar->csts, bar->u_cc,
			    bar->u_csts);
		/* Enable */
		if (bar->cc.en == 1) {
			if (nvmev_vdev->admin_q) {
				bar->csts.rdy = 1;
			} else {
				WARN_ON("Enable device without init admin q");
			}
		} else if (bar->cc.en == 0) {
			bar->csts.rdy = 0;
		}

		/* Shutdown */
		if (bar->cc.shn == 1) {
			bar->csts.shst = 2;

			nvmev_vdev->dbs[0] = nvmev_vdev->old_dbs[0] = 0;
			nvmev_vdev->dbs[1] = nvmev_vdev->old_dbs[1] = 0;
			nvmev_vdev->admin_q->cq_head = 0;
		}

		old_bar->cc = bar->u_cc;

		goto out;
	}
out:
	smp_mb();
	return;
}

int nvmev_pci_read(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 *val)
{
	if (devfn != 0)
		return 1;

	memcpy(val, nvmev_vdev->virtDev + where, size);

	NVMEV_DEBUG("[R] target: %x, size: %d, val: %x\n", where, size, *val);

	return 0;
};

int nvmev_pci_write(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 _val)
{
	u32 mask = ~(0U);
	u32 val = 0x00;
	int target = where;

	WARN_ON(size > sizeof(_val));

	memcpy(&val, nvmev_vdev->virtDev + where, size);

	if (where < OFFS_PCI_PM_CAP) {
		// PCI_HDR
		if (target == PCI_COMMAND) {
			mask = PCI_COMMAND_INTX_DISABLE;
			if ((val ^ _val) & PCI_COMMAND_INTX_DISABLE) {
				nvmev_vdev->intx_disabled = !!(_val & PCI_COMMAND_INTX_DISABLE);
				if (!nvmev_vdev->intx_disabled) {
					nvmev_vdev->pcihdr->sts.is = 0;
				}
			}
		} else if (target == PCI_STATUS) {
			mask = 0xF200;
		} else if (target == PCI_BIST) {
			mask = PCI_BIST_START;
		} else if (target == PCI_BASE_ADDRESS_0) {
			mask = 0xFFFFC000;
		} else if (target == PCI_INTERRUPT_LINE) {
			mask = 0xFF;
		} else {
			mask = 0x0;
		}
	} else if (where < OFFS_PCI_MSIX_CAP) {
		// PCI_PM_CAP
	} else if (where < OFFS_PCIE_CAP) {
		// PCI_MSIX_CAP
		target -= OFFS_PCI_MSIX_CAP;
		if (target == PCI_MSIX_FLAGS) {
			mask = PCI_MSIX_FLAGS_MASKALL | /* 0x4000 */
			       PCI_MSIX_FLAGS_ENABLE; /* 0x8000 */

			if ((nvmev_vdev->pdev) && ((val ^ _val) & PCI_MSIX_FLAGS_ENABLE)) {
				nvmev_vdev->pdev->msix_enabled = !!(_val & PCI_MSIX_FLAGS_ENABLE);
			}
		} else {
			mask = 0x0;
		}
	} else {
		// PCIE_CAP
	}
	NVMEV_DEBUG("[W] 0x%x, mask: 0x%x, val: 0x%x -> 0x%x, size: %d, new: 0x%x\n", where, mask,
		    val, _val, size, (val & (~mask)) | (_val & mask));

	val = (val & (~mask)) | (_val & mask);
	memcpy(nvmev_vdev->virtDev + where, &val, size);

	return 0;
};

static void __dump_pci_dev(struct pci_dev *dev)
{
	NVMEV_DEBUG("bus: %p, subordinate: %p\n", dev->bus, dev->subordinate);
	NVMEV_DEBUG("vendor: %x, device: %x\n", dev->vendor, dev->device);
	NVMEV_DEBUG("s_vendor: %x, s_device: %x\n", dev->subsystem_vendor, dev->subsystem_device);
	NVMEV_DEBUG("devfn: %u, class: %x\n", dev->devfn, dev->class);
	NVMEV_DEBUG("sysdata: %p, slot: %p\n", dev->sysdata, dev->slot);
	NVMEV_DEBUG("pin: %d, irq: %u\n", dev->pin, dev->irq);
	NVMEV_DEBUG("msi: %d, msi-x:%d\n", dev->msi_enabled, dev->msix_enabled);
	NVMEV_DEBUG("resource[0]: %llx\n", pci_resource_start(dev, 0));
}

static struct pci_bus *__create_pci_bus(void)
{
	struct pci_bus *bus = NULL;
	struct pci_dev *dev;

	nvmev_vdev->pci_ops = (struct pci_ops){
		.read = nvmev_pci_read,
		.write = nvmev_pci_write,
	};

	nvmev_vdev->pci_sysdata = (struct pci_sysdata){
		.domain = NVMEV_PCI_DOMAIN_NUM,
		.node = cpu_to_node(nvmev_vdev->config.cpu_nr_dispatcher),
	};

	bus = pci_scan_bus(NVMEV_PCI_BUS_NUM, &nvmev_vdev->pci_ops, &nvmev_vdev->pci_sysdata);

	if (!bus) {
		NVMEV_ERROR("Unable to create PCI bus\n");
		return NULL;
	}

	/* XXX Only support a singe NVMeVirt instance in the system for now */
	list_for_each_entry(dev, &bus->devices, bus_list) {
		struct resource *res = &dev->resource[0];
		res->parent = &iomem_resource;

		nvmev_vdev->pdev = dev;
		dev->irq = NVMEV_INTX_IRQ;

		__dump_pci_dev(dev);

		nvmev_vdev->bar = memremap(pci_resource_start(dev, 0), PAGE_SIZE * 2, MEMREMAP_WT);
		memset(nvmev_vdev->bar, 0x0, PAGE_SIZE * 2);

		nvmev_vdev->dbs = ((void *)nvmev_vdev->bar) + PAGE_SIZE;

		nvmev_vdev->bar->vs.mjr = 1;
		nvmev_vdev->bar->vs.mnr = 0;
		nvmev_vdev->bar->cap.mpsmin = 0;
		nvmev_vdev->bar->cap.mqes = 1024 - 1; // 0-based value

#if (SUPPORTED_SSD_TYPE(ZNS))
		nvmev_vdev->bar->cap.css = CAP_CSS_BIT_SPECIFIC;
#endif

		nvmev_vdev->old_dbs = kzalloc(PAGE_SIZE, GFP_KERNEL);
		BUG_ON(!nvmev_vdev->old_dbs && "allocating old DBs memory");
		memcpy(nvmev_vdev->old_dbs, nvmev_vdev->dbs, sizeof(*nvmev_vdev->old_dbs));

		nvmev_vdev->old_bar = kzalloc(PAGE_SIZE, GFP_KERNEL);
		BUG_ON(!nvmev_vdev->old_bar && "allocating old BAR memory");
		memcpy(nvmev_vdev->old_bar, nvmev_vdev->bar, sizeof(*nvmev_vdev->old_bar));

		nvmev_vdev->msix_table =
			memremap(pci_resource_start(nvmev_vdev->pdev, 0) + PAGE_SIZE * 2,
				 NR_MAX_IO_QUEUE * PCI_MSIX_ENTRY_SIZE, MEMREMAP_WT);
		memset(nvmev_vdev->msix_table, 0x00, NR_MAX_IO_QUEUE * PCI_MSIX_ENTRY_SIZE);
	}

	NVMEV_INFO("Successfully created virtual PCI bus (node %d)\n",
		   nvmev_vdev->pci_sysdata.node);

	return bus;
};

struct nvmev_dev *VDEV_INIT(void)
{
	struct nvmev_dev *nvmev_vdev;
	nvmev_vdev = kzalloc(sizeof(*nvmev_vdev), GFP_KERNEL);

	nvmev_vdev->virtDev = kzalloc(PAGE_SIZE, GFP_KERNEL);

	nvmev_vdev->pcihdr = nvmev_vdev->virtDev + OFFS_PCI_HDR;
	nvmev_vdev->pmcap = nvmev_vdev->virtDev + OFFS_PCI_PM_CAP;
	nvmev_vdev->msixcap = nvmev_vdev->virtDev + OFFS_PCI_MSIX_CAP;
	nvmev_vdev->pciecap = nvmev_vdev->virtDev + OFFS_PCIE_CAP;
	nvmev_vdev->aercap = nvmev_vdev->virtDev + PCI_CFG_SPACE_SIZE;
	nvmev_vdev->pcie_exp_cap = nvmev_vdev->virtDev + PCI_CFG_SPACE_SIZE;

	nvmev_vdev->admin_q = NULL;

	return nvmev_vdev;
}

void VDEV_FINALIZE(struct nvmev_dev *nvmev_vdev)
{
	if (nvmev_vdev->msix_table)
		memunmap(nvmev_vdev->msix_table);

	if (nvmev_vdev->bar)
		memunmap(nvmev_vdev->bar);

	if (nvmev_vdev->old_bar)
		kfree(nvmev_vdev->old_bar);

	if (nvmev_vdev->old_dbs)
		kfree(nvmev_vdev->old_dbs);

	if (nvmev_vdev->admin_q) {
		if (nvmev_vdev->admin_q->nvme_cq)
			kfree(nvmev_vdev->admin_q->nvme_cq);

		if (nvmev_vdev->admin_q->nvme_sq)
			kfree(nvmev_vdev->admin_q->nvme_sq);

		kfree(nvmev_vdev->admin_q);
	}

	if (nvmev_vdev->virtDev)
		kfree(nvmev_vdev->virtDev);

	if (nvmev_vdev)
		kfree(nvmev_vdev);
}

void PCI_HEADER_SETTINGS(struct pci_header *pcihdr, unsigned long base_pa)
{
	pcihdr->id.did = 0x0101;
	pcihdr->id.vid = 0x0c51;
	/*
	pcihdr->cmd.id = 1;
	pcihdr->cmd.bme = 1;
	*/
	pcihdr->cmd.mse = 1;
	pcihdr->sts.cl = 1;

	pcihdr->htype.mfd = 0;
	pcihdr->htype.hl = PCI_HEADER_TYPE_NORMAL;

	pcihdr->rid = 0x01;

	pcihdr->cc.bcc = PCI_BASE_CLASS_STORAGE;
	pcihdr->cc.scc = 0x08;
	pcihdr->cc.pi = 0x02;

	pcihdr->mlbar.tp = PCI_BASE_ADDRESS_MEM_TYPE_64 >> 1;
	pcihdr->mlbar.ba = (base_pa & 0xFFFFFFFF) >> 14;

	pcihdr->mulbar = base_pa >> 32;

	pcihdr->ss.ssid = 0x370d;
	pcihdr->ss.ssvid = 0x0c51;

	pcihdr->erom = 0x0;

	pcihdr->cap = OFFS_PCI_PM_CAP;

	pcihdr->intr.ipin = 0;
	pcihdr->intr.iline = NVMEV_INTX_IRQ;
}

void PCI_PMCAP_SETTINGS(struct pci_pm_cap *pmcap)
{
	pmcap->pid.cid = PCI_CAP_ID_PM;
	pmcap->pid.next = OFFS_PCI_MSIX_CAP;

	pmcap->pc.vs = 3;
	pmcap->pmcs.nsfrst = 1;
	pmcap->pmcs.ps = PCI_PM_CAP_PME_D0 >> 16;
}

void PCI_MSIXCAP_SETTINGS(struct pci_msix_cap *msixcap)
{
	msixcap->mxid.cid = PCI_CAP_ID_MSIX;
	msixcap->mxid.next = OFFS_PCIE_CAP;

	msixcap->mxc.mxe = 1;
	msixcap->mxc.ts = 127; // encoded as n-1

	msixcap->mtab.tbir = 0;
	msixcap->mtab.to = 0x400;

	msixcap->mpba.pbao = 0x1000;
	msixcap->mpba.pbir = 0;
}

void PCI_PCIECAP_SETTINGS(struct pcie_cap *pciecap)
{
	pciecap->pxid.cid = PCI_CAP_ID_EXP;
	pciecap->pxid.next = 0x0;

	pciecap->pxcap.ver = PCI_EXP_FLAGS;
	pciecap->pxcap.imn = 0;
	pciecap->pxcap.dpt = PCI_EXP_TYPE_ENDPOINT;

	pciecap->pxdcap.mps = 1;
	pciecap->pxdcap.pfs = 0;
	pciecap->pxdcap.etfs = 1;
	pciecap->pxdcap.l0sl = 6;
	pciecap->pxdcap.l1l = 2;
	pciecap->pxdcap.rer = 1;
	pciecap->pxdcap.csplv = 0;
	pciecap->pxdcap.cspls = 0;
	pciecap->pxdcap.flrc = 1;
}

void PCI_AERCAP_SETTINGS(struct aer_cap *aercap)
{
	aercap->aerid.cid = PCI_EXT_CAP_ID_ERR;
	aercap->aerid.cver = 1;
	aercap->aerid.next = PCI_CFG_SPACE_SIZE + 0x50;
}

void PCI_PCIE_EXTCAP_SETTINGS(struct pci_exp_hdr *exp_cap)
{
	struct pci_exp_hdr *pcie_exp_cap;

	pcie_exp_cap = exp_cap + 0x50;
	pcie_exp_cap->id.cid = PCI_EXT_CAP_ID_VC;
	pcie_exp_cap->id.cver = 1;
	pcie_exp_cap->id.next = PCI_CFG_SPACE_SIZE + 0x80;

	pcie_exp_cap = exp_cap + 0x80;
	pcie_exp_cap->id.cid = PCI_EXT_CAP_ID_PWR;
	pcie_exp_cap->id.cver = 1;
	pcie_exp_cap->id.next = PCI_CFG_SPACE_SIZE + 0x90;

	pcie_exp_cap = exp_cap + 0x90;
	pcie_exp_cap->id.cid = PCI_EXT_CAP_ID_ARI;
	pcie_exp_cap->id.cver = 1;
	pcie_exp_cap->id.next = PCI_CFG_SPACE_SIZE + 0x170;

	pcie_exp_cap = exp_cap + 0x170;
	pcie_exp_cap->id.cid = PCI_EXT_CAP_ID_DSN;
	pcie_exp_cap->id.cver = 1;
	pcie_exp_cap->id.next = PCI_CFG_SPACE_SIZE + 0x1a0;

	pcie_exp_cap = exp_cap + 0x1a0;
	pcie_exp_cap->id.cid = PCI_EXT_CAP_ID_SECPCI;
	pcie_exp_cap->id.cver = 1;
	pcie_exp_cap->id.next = 0;
}

bool NVMEV_PCI_INIT(struct nvmev_dev *nvmev_vdev)
{
	PCI_HEADER_SETTINGS(nvmev_vdev->pcihdr, nvmev_vdev->config.memmap_start);
	PCI_PMCAP_SETTINGS(nvmev_vdev->pmcap);
	PCI_MSIXCAP_SETTINGS(nvmev_vdev->msixcap);
	PCI_PCIECAP_SETTINGS(nvmev_vdev->pciecap);
	PCI_AERCAP_SETTINGS(nvmev_vdev->aercap);
	PCI_PCIE_EXTCAP_SETTINGS(nvmev_vdev->pcie_exp_cap);

#ifdef CONFIG_NVMEV_FAST_X86_IRQ_HANDLING
	__init_apicid_to_cpuid();
#endif
	nvmev_vdev->intx_disabled = false;

	nvmev_vdev->virt_bus = __create_pci_bus();
	if (!nvmev_vdev->virt_bus)
		return false;

	return true;
}

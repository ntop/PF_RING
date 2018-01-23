AMD Processors
==============

If you decided to move to AMD RYZEN or EPYC CPUs you probably experienced 
issues running PF_RING ZC, this is because application memory is provided 
to the network card (for directly moving packets with DMA) translating virtual 
addresses into physical addresses, and the IOMMU does not like it.
In order to run PF_RING ZC on those processors you need to disable IOMMU support, 
you can do this following the steps below:

1. Set 'IOMMU' to 'Disabled' in your BIOS
2. Disable amd_iommu in your GRUB boot parameters appending 'amd_iommu=off'

Now you are ready to run ZC.

